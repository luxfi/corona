// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

// no_reconstruct_sign_test.go — the headline STRUCTURAL + BEHAVIOURAL proof
// that the Corona threshold SIGNING path is no-reconstruct: no party and no
// aggregator ever forms the full secret key s (or reconstructs it from shares)
// during signing, not even transiently. This is gate 5 of the trustless-by-
// default law (a reveal-and-aggregate / reconstruct-at-coordinator signing
// path is NOT a strict trustless lane).
//
// It mirrors the established pattern:
//   - luxfi/dkg vss/noreconstruct_test.go  (go/ast structural scan of the path)
//   - luxfi/pulsar no_reconstruct_committee_test.go  (combiner-sees-no-secret +
//     independent-verifier gates)
//
// THE CRYPTOGRAPHIC DISTINCTION (why this scan is NOT vss's scan verbatim).
// Corona is threshold-Raccoon / Module-LWE. Its no-reconstruct signing works by
// each party computing, LOCALLY and from its OWN share only,
//
//	z_i = R_i·u + maskPrime_i + (λ_i · s_i · c) − mask_i        (sign.SignRound2)
//
// and the aggregator summing the MASKED partials
//
//	z   = Σ_j z_j = Σ_j R_j·u + c·Σ_j λ_j·s_j  =  R·u + c·s     (sign.SignFinalize)
//
// The secret s = Σ_j λ_j·s_j appears ONLY as the coefficient of the public
// challenge c inside the aggregated, nonce-masked z; it is NEVER materialised.
// Crucially, the per-party Lagrange coefficient λ_i (party.Lambda) applied to
// the party's OWN share s_i IS the no-reconstruct mechanism — so, unlike vss
// (whose DKG output path derives the group key from PUBLIC commits and touches
// no Lagrange at all), this scan deliberately does NOT forbid per-party
// Lagrange. What it forbids is the ACROSS-PARTY recombination of shares into s
// (Lagrange-interpolation-at-0 / Shamir recombination). party.Lambda is read as
// a struct field, never as a call, so the call-target scan leaves it untouched.
//
// CLAIM DISCIPLINE. What this proves: "Corona threshold signing is
// no-reconstruct — the signing functions form no full secret and never invoke
// the trusted-dealer keygen; the only artifacts exchanged between parties carry
// no share; and the no-reconstruct ceremony's output verifies under the
// independent Corona verifier." Keygen is a SEPARATE concern: the production
// chain uses the dealerless keyera.Bootstrap (Pedersen VSS, no party ever holds
// s); sign.Gen / GenerateKeysTrustedDealer are the opt-in trusted-dealer KEYGEN
// footgun (loudly documented), and this proof's second arm is precisely that
// the signing path never reaches them.

import (
	"bytes"
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"

	"github.com/luxfi/corona/sign"
)

// ─────────────────────────────────────────────────────────────────────────
// GATE A (structural) — the signing functions reconstruct no secret.
// ─────────────────────────────────────────────────────────────────────────

// signPathFiles are the non-test source files that implement the Corona
// threshold signing + verification path. Paths are relative to this package
// dir (corona/threshold); the sign-kernel files live one directory up.
var signPathFiles = []string{
	"../sign/sign.go",
	"../sign/config.go",
	"threshold.go",
	"wire.go",
	"verify_batch.go",
}

// signingFuncs is the EXACT set of load-bearing signing + verification
// functions whose bodies must be proven reconstruct-free. Verification helpers
// are included for completeness (they consume only public data). KEYGEN
// functions (Gen, GenerateKeysTrustedDealer) are deliberately ABSENT — they
// legitimately form s and are carved out below.
var signingFuncs = map[string]bool{
	// sign kernel — the 2-round protocol + finalize.
	"SignRound1":           true,
	"SignRound2Preprocess": true,
	"SignRound2":           true,
	"SignFinalize":         true,
	// sign kernel — public verifier.
	"Verify":          true,
	"VerifyWithSuite": true,
	"CheckL2Norm":     true,
	// threshold orchestration — single-party signer + aggregate + verify.
	"NewSigner":      true,
	"Round1":         true,
	"Round2":         true,
	"Finalize":       true,
	"VerifyBytes":    true,
	"VerifyBatch":    true,
	"VerifyBatchAll": true,
}

// mustSeeSigningFuncs are the signing functions that MUST be found and
// inspected for the scan to be non-vacuous. If any is renamed/removed the test
// fails loudly rather than silently passing on an empty scan.
var mustSeeSigningFuncs = []string{
	"SignRound1", "SignRound2Preprocess", "SignRound2", "SignFinalize",
	"NewSigner", "Round1", "Round2", "Finalize",
}

// keygenFuncs FORM or Shamir-share the master secret s. They are the ONLY
// functions permitted to touch the full secret, they are KEYGEN not signing,
// and the production chain replaces them with the dealerless keyera.Bootstrap.
// The structural proof's second arm: NO signing function calls one of these.
var keygenFuncs = map[string]bool{
	"Gen":                       true,
	"GenerateKeysTrustedDealer": true,
}

// forbiddenReconstruct are call-target identifier substrings that denote
// forming the FULL secret s = Σ_j λ_j·s_j across parties (Lagrange
// interpolation at 0 / Shamir recombination / share-combining / reshare master
// recovery). Per-party Lagrange (party.Lambda applied to the party's OWN share)
// is the legitimate no-reconstruct mechanism and is intentionally NOT here — it
// is a field read, not a call, and denotes no across-party recombination.
var forbiddenReconstruct = []string{
	"reconstruct",
	"interpolate",
	"combineshare",
	"recoversecret",
	"recovershamir",
	"recoverpoly",
	"shamirsecretsharing",
	"lagrangeatzero",
	"selectquorum",
}

// calleeName extracts the called function's identifier from a call expression:
// the bare name for f(...) and the selector tail for pkg.F(...) / x.M(...).
func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// TestNoReconstruct_Sign_SourceStructural parses every signing/verification
// function in the Corona sign path with go/ast (comments excluded, so prose
// never trips the scan) and asserts that no function body (a) calls an
// across-party secret-reconstruction primitive, or (b) invokes the
// trusted-dealer keygen that forms s. Together these prove the signing path
// never reconstructs the secret.
func TestNoReconstruct_Sign_SourceStructural(t *testing.T) {
	fset := token.NewFileSet()
	seen := map[string]bool{}
	inspectedFuncs := 0

	for _, path := range signPathFiles {
		file, err := parser.ParseFile(fset, path, nil, 0) // 0 = drop comments
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			if !signingFuncs[name] {
				continue // not a signing/verify function (e.g. Gen keygen, helpers)
			}
			seen[name] = true
			inspectedFuncs++

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee := calleeName(call)
				low := strings.ToLower(callee)

				for _, bad := range forbiddenReconstruct {
					if strings.Contains(low, bad) {
						t.Errorf("%s: signing function %q CALLS %q (matches forbidden reconstruction primitive %q) — the signing path must never recombine shares into s",
							path, name, callee, bad)
					}
				}
				if keygenFuncs[callee] {
					t.Errorf("%s: signing function %q CALLS keygen %q which forms the full secret s — signing must not reach the trusted-dealer keygen (use the dealerless keyera.Bootstrap shares)",
						path, name, callee)
				}
				return true
			})
		}
	}

	if inspectedFuncs == 0 {
		t.Fatal("no signing functions inspected — scan is vacuous (paths or names drifted)")
	}
	for _, want := range mustSeeSigningFuncs {
		if !seen[want] {
			t.Errorf("expected signing function %q was not found in the scanned sign path — the scan is incomplete (rename?), refusing to certify no-reconstruct", want)
		}
	}
	t.Logf("GATE A (structural) PASS: %d signing/verify functions inspected; none recombines shares into s nor invokes the trusted-dealer keygen", inspectedFuncs)
}

// ─────────────────────────────────────────────────────────────────────────
// GATE B (behavioural, type) — the artifacts exchanged between parties, and
// the aggregator's inputs, carry NO secret. The aggregator therefore cannot
// reconstruct s even in principle: it never receives a second party's share.
// ─────────────────────────────────────────────────────────────────────────

// secretFieldNameTokens are field-name substrings that denote secret key
// material. None may appear on an inter-party message or on the final
// signature. (MAC tags — field "MACs" — are NOT secrets: they are
// authentication codes broadcast to bind the D matrix, and "macs" matches no
// token below.)
var secretFieldNameTokens = []string{
	"skshare", "share", "secret", "seed", "lambda",
	"mackey", "privatekey", "master", "prfkey",
}

// secretFieldTypeTokens are type-string substrings that must never ride an
// inter-party message: the per-party KeyShare struct above all.
var secretFieldTypeTokens = []string{"KeyShare"}

func assertNoSecretFields(t *testing.T, what string, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		ln := strings.ToLower(f.Name)
		for _, tok := range secretFieldNameTokens {
			if strings.Contains(ln, tok) {
				t.Errorf("%s.%s — secret-bearing field name (matches %q) on a no-secret artifact", what, f.Name, tok)
			}
		}
		ts := f.Type.String()
		for _, tok := range secretFieldTypeTokens {
			if strings.Contains(ts, tok) {
				t.Errorf("%s.%s has secret-bearing type %s (matches %q)", what, f.Name, ts, tok)
			}
		}
	}
}

// TestNoReconstruct_Sign_CombinerSeesNoSecret reflects over every artifact that
// crosses between parties (Round1Data, Round2Data) and the final Signature, and
// asserts none carries a share / sk / seed / Lagrange coefficient. The
// aggregator's Finalize ingests only map[int]*Round2Data — masked z partials —
// so it structurally cannot recombine shares: it never holds a second party's
// secret.
func TestNoReconstruct_Sign_CombinerSeesNoSecret(t *testing.T) {
	assertNoSecretFields(t, "Round1Data", reflect.TypeOf(Round1Data{}))
	assertNoSecretFields(t, "Round2Data", reflect.TypeOf(Round2Data{}))
	assertNoSecretFields(t, "Signature", reflect.TypeOf(Signature{}))

	// Finalize's only per-signer input is the value type of its map parameter.
	// Pin that it is *Round2Data (the masked response), NOT *KeyShare.
	finalize, ok := reflect.TypeOf(&Signer{}).MethodByName("Finalize")
	if !ok {
		t.Fatal("Signer has no Finalize method — signing surface drifted")
	}
	// method type: func(*Signer, map[int]*Round2Data) (*Signature, error)
	ft := finalize.Func.Type()
	if ft.NumIn() != 2 {
		t.Fatalf("Finalize arity changed: got %d params (want receiver + 1)", ft.NumIn())
	}
	in := ft.In(1)
	if in.Kind() != reflect.Map || in.Elem() != reflect.TypeOf(&Round2Data{}) {
		t.Fatalf("Finalize ingests %s — the aggregator's input must be map[int]*Round2Data (masked partials), never a share type", in)
	}
	t.Logf("GATE B (behavioural) PASS: Round1Data/Round2Data/Signature carry no secret; aggregator ingests only masked z partials")
}

// ─────────────────────────────────────────────────────────────────────────
// GATE C (independent verifier) — a real no-reconstruct ceremony, where every
// Signer is constructed from exactly ONE share and parties exchange only the
// public Round1Data/Round2Data, produces a signature that the independent
// Corona verifier (sign.Verify, public data only) accepts; tamper is rejected.
// ─────────────────────────────────────────────────────────────────────────

func TestNoReconstruct_Sign_VerifiesUnderIndependentVerifier(t *testing.T) {
	const tt, n = 3, 5
	shares, gk, err := GenerateKeysTrustedDealer(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("keygen (%d,%d): %v", tt, n, err)
	}

	// Custody: each signer holds exactly ONE distinct share. No signer is ever
	// handed another party's KeyShare — the no-reconstruct custody invariant.
	signers := make([]*Signer, n)
	seenIdx := map[int]bool{}
	for i, sh := range shares {
		if seenIdx[sh.Index] {
			t.Fatalf("share index %d duplicated — single-share custody violated", sh.Index)
		}
		seenIdx[sh.Index] = true
		signers[i] = NewSigner(sh)
	}

	signerIDs := make([]int, n)
	for i := range signerIDs {
		signerIDs[i] = i
	}
	const sid = 1
	prfKey := make([]byte, 32)
	if _, err := rand.Read(prfKey); err != nil {
		t.Fatal(err)
	}
	msg := "corona no-reconstruct ceremony: independent verify"

	// Round 1 — each party broadcasts only D + MACs (Round1Data: no share).
	r1 := make(map[int]*Round1Data, n)
	for _, s := range signers {
		d, err := s.Round1(sid, prfKey, signerIDs)
		if err != nil {
			t.Fatalf("Round1 party %d: %v", s.share.Index, err)
		}
		r1[d.PartyID] = d
	}
	// Round 2 — each party emits only its masked z partial (Round2Data).
	r2 := make(map[int]*Round2Data, n)
	for _, s := range signers {
		d, err := s.Round2(sid, msg, prfKey, signerIDs, r1)
		if err != nil {
			t.Fatalf("Round2 party %d: %v", s.share.Index, err)
		}
		r2[d.PartyID] = d
	}
	// Finalize — aggregator (party 0) sums masked partials; forms no secret.
	sig, err := signers[0].Finalize(r2)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// Independent verifier: the bare Corona verifier over PUBLIC data only
	// (A, BTilde, z, c, Delta) — no signing/keygen state in the loop.
	if !sign.Verify(
		gk.Params.R, gk.Params.RXi, gk.Params.RNu,
		sig.Z, gk.A, msg, gk.BTilde, sig.C, sig.Delta,
	) {
		t.Fatal("GATE C FAILED: independent Corona verifier REJECTED the no-reconstruct signature")
	}

	// Negative control: a one-character message tamper must be rejected.
	bad := msg + "!"
	if sign.Verify(
		gk.Params.R, gk.Params.RXi, gk.Params.RNu,
		sig.Z, gk.A, bad, gk.BTilde, sig.C, sig.Delta,
	) {
		t.Fatal("GATE C FAILED: independent verifier accepted a tampered message — binding broken")
	}

	// And via the stateless wire verifier (bytes-in, bool-out) for parity.
	gkBytes, err := gk.MarshalBinary()
	if err != nil {
		t.Fatalf("group key marshal: %v", err)
	}
	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		t.Fatalf("signature marshal: %v", err)
	}
	if !VerifyBytes(gkBytes, msg, sigBytes) {
		t.Fatal("GATE C FAILED: stateless wire verifier rejected the no-reconstruct signature")
	}
	if VerifyBytes(gkBytes, bad, sigBytes) {
		t.Fatal("GATE C FAILED: stateless wire verifier accepted a tampered message")
	}

	if bytes.Equal(gkBytes, sigBytes) {
		t.Fatal("group key and signature serialised identically — impossible, codec broken")
	}
	t.Logf("GATE C PASS: (%d,%d) no-reconstruct ceremony verifies under the independent Corona verifier; tamper rejected. Sub-quorum-cannot-forge is pinned separately by TestThresholdSubQuorumCannotForge.", tt, n)
}
