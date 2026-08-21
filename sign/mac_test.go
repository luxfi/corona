// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sign

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/luxfi/corona/primitives"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// TestMACComparisonIsConstantTime scans the Round-2 preprocess for the tag
// comparison and asserts it goes through crypto/subtle.
//
// The MAC on the left of that comparison arrives from a peer; the MAC on the
// right is computed under a key only the pair shares. bytes.Equal returns on
// the first differing byte, so the time it takes tells the peer how many
// leading bytes of its guess were right — a forgery oracle over the pairwise
// key. isZero32, ten lines above, already uses subtle for a value no
// adversary supplies; the adversary-supplied one is the comparison that has
// to be branch-free.
func TestMACComparisonIsConstantTime(t *testing.T) {
	fn := parseFunc(t, "sign.go", "SignRound2Preprocess")

	var variable []string
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name := qualifiedCallee(call); name == "bytes.Equal" || name == "bytes.Compare" {
			variable = append(variable, name)
		}
		return true
	})

	for _, name := range variable {
		t.Errorf("SignRound2Preprocess compares a peer-supplied MAC with %s; "+
			"use subtle.ConstantTimeCompare so the comparison does not leak the "+
			"length of the matching prefix", name)
	}
}

// TestSignRound2PreprocessRejectsForgedMAC is the behavioural companion: a tag
// that was not produced under the pairwise key must fail the gate whatever it
// looks like — wrong bytes, truncated, extended, absent.
func TestSignRound2PreprocessRejectsForgedMAC(t *testing.T) {
	party, A, T := newReuseTestParty(t)

	D, macs, err := party.SignRound1(A, 1, []byte("prf"), T)
	if err != nil {
		t.Fatalf("SignRound1: %v", err)
	}
	_ = macs

	// Every peer ships the same D; only the tags they authenticate it with
	// vary. Party 0 verifies the tags addressed to it.
	honest := func() map[int]map[int][]byte {
		out := make(map[int]map[int][]byte, len(T))
		for _, j := range T {
			if j == party.ID {
				continue
			}
			out[j] = map[int][]byte{
				party.ID: primitives.GenerateMAC(party.Suite, D, party.MACKeys[j], party.ID, 1, T, j, true),
			}
		}
		return out
	}
	dmap := make(map[int]structs.Matrix[ring.Poly], len(T))
	for _, j := range T {
		dmap[j] = D
	}
	b := structs.Vector[ring.Poly](nil)

	if ok, _, _ := party.SignRound2Preprocess(A, b, dmap, honest(), 1, T); !ok {
		t.Fatal("honest tags rejected — the positive control does not hold, the negatives below prove nothing")
	}

	for _, c := range []struct {
		name  string
		spoil func([]byte) []byte
	}{
		{"flipped first byte", func(m []byte) []byte { out := append([]byte(nil), m...); out[0] ^= 1; return out }},
		{"flipped last byte", func(m []byte) []byte { out := append([]byte(nil), m...); out[len(out)-1] ^= 1; return out }},
		{"truncated", func(m []byte) []byte { return m[:len(m)-1] }},
		{"extended", func(m []byte) []byte { return append(append([]byte(nil), m...), 0) }},
		{"empty", func(m []byte) []byte { return []byte{} }},
		{"absent", func(m []byte) []byte { return nil }},
	} {
		t.Run(c.name, func(t *testing.T) {
			macs := honest()
			for j := range macs {
				macs[j][party.ID] = c.spoil(macs[j][party.ID])
			}
			if ok, _, _ := party.SignRound2Preprocess(A, b, dmap, macs, 1, T); ok {
				t.Errorf("a %s tag passed the round-2 gate", c.name)
			}
		})
	}
}

// parseFunc returns the named top-level function declaration from a source
// file of this package. It fails loudly when the name is absent so a rename
// cannot turn a scan into a vacuous pass.
func parseFunc(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("%s: no function named %s — the scan has nothing to look at", file, name)
	return nil
}

// qualifiedCallee renders a call target as "pkg.Func", or "" when the target
// is not a package-qualified identifier.
func qualifiedCallee(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return pkg.Name + "." + sel.Sel.Name
}
