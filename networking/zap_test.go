// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package networking

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func bufioNewReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }
func bufioNewWriter(w io.Writer) *bufio.Writer { return bufio.NewWriter(w) }

// newSilentLogger returns a slog.Logger that discards everything. Used
// in benchmarks so the per-iteration log overhead does not pollute
// timing numbers.
func newSilentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// freePort grabs a free TCP port for the test by binding to :0,
// reading the assigned port, and closing — the kernel may reuse the
// port for the test listener microseconds later.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// twoPartyZAP brings up two P2PComm instances over ZAP and wires them
// to each other. Returns the two comms plus a cleanup func.
func twoPartyZAP(t *testing.T) (*P2PComm, *P2PComm, func()) {
	t.Helper()
	port0 := freePort(t)
	port1 := freePort(t)
	silent := newSilentLogger()

	comm0, err := NewP2PComm(0, port0, true /*noDiscovery*/, silent)
	if err != nil {
		t.Fatalf("NewP2PComm 0: %v", err)
	}
	comm1, err := NewP2PComm(1, port1, true /*noDiscovery*/, silent)
	if err != nil {
		comm0.Close()
		t.Fatalf("NewP2PComm 1: %v", err)
	}

	// Lower-rank side dials, higher-rank side accepts (Corona's
	// historical convention preserved in EstablishConnectionsZAP).
	addr1 := fmt.Sprintf("127.0.0.1:%d", port1)
	comm0.AcceptPeer(1) // local registers 1's NodeID
	if err := comm0.Connect(1, addr1); err != nil {
		comm0.Close()
		comm1.Close()
		t.Fatalf("Connect 0->1: %v", err)
	}
	comm1.AcceptPeer(0)

	// Allow the listener side a moment to register the inbound conn.
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		comm0.Close()
		comm1.Close()
	}
	return comm0, comm1, cleanup
}

func TestZAP_SendRecvVector(t *testing.T) {
	comm0, comm1, cleanup := twoPartyZAP(t)
	defer cleanup()

	r, _ := ring.NewRing(256, []uint64{8380417})
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	testVector := make(structs.Vector[ring.Poly], 3)
	for i := range testVector {
		testVector[i] = sampler.ReadNew()
	}

	var received structs.Vector[ring.Poly]
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		received = comm1.RecvVector(nil, 0, len(testVector))
	}()

	comm0.SendVector(nil, 1, testVector)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ZAP vector recv timed out")
	}

	if len(received) != len(testVector) {
		t.Fatalf("len: got %d want %d", len(received), len(testVector))
	}
	for i := range testVector {
		if !r.Equal(received[i], testVector[i]) {
			t.Errorf("vec[%d] mismatch", i)
		}
	}
}

func TestZAP_SendRecvMatrix(t *testing.T) {
	comm0, comm1, cleanup := twoPartyZAP(t)
	defer cleanup()

	r, _ := ring.NewRing(256, []uint64{8380417})
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	testMatrix := make(structs.Matrix[ring.Poly], 2)
	for i := range testMatrix {
		testMatrix[i] = make(structs.Vector[ring.Poly], 3)
		for j := range testMatrix[i] {
			testMatrix[i][j] = sampler.ReadNew()
		}
	}

	var received structs.Matrix[ring.Poly]
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		received = comm1.RecvMatrix(nil, 0, len(testMatrix))
	}()

	comm0.SendMatrix(nil, 1, testMatrix)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ZAP matrix recv timed out")
	}

	if len(received) != len(testMatrix) {
		t.Fatalf("rows: got %d want %d", len(received), len(testMatrix))
	}
	for i := range testMatrix {
		if len(received[i]) != len(testMatrix[i]) {
			t.Errorf("row %d cols: got %d want %d", i, len(received[i]), len(testMatrix[i]))
		}
		for j := range testMatrix[i] {
			if !r.Equal(received[i][j], testMatrix[i][j]) {
				t.Errorf("matrix[%d][%d] mismatch", i, j)
			}
		}
	}
}

func TestZAP_SendRecvBytesSlice(t *testing.T) {
	comm0, comm1, cleanup := twoPartyZAP(t)
	defer cleanup()

	in := [][]byte{
		[]byte("round 1 share"),
		[]byte("round 2 nonce-commitment"),
		[]byte("round 3 signature share"),
	}

	var out [][]byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out = comm1.RecvBytesSlice(nil, 0)
	}()
	comm0.SendBytesSlice(nil, 1, in)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ZAP bytes-slice recv timed out")
	}

	if len(out) != len(in) {
		t.Fatalf("len: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if !bytes.Equal(out[i], in[i]) {
			t.Errorf("slice[%d]: got %q want %q", i, out[i], in[i])
		}
	}
}

func TestZAP_SendRecvBytesMap(t *testing.T) {
	comm0, comm1, cleanup := twoPartyZAP(t)
	defer cleanup()

	in := map[int][]byte{
		0: []byte("party-0-share"),
		1: []byte("party-1-share"),
		2: []byte("party-2-share"),
	}

	var out map[int][]byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out = comm1.RecvBytesMap(nil, 0)
	}()
	comm0.SendBytesMap(nil, 1, in)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ZAP bytes-map recv timed out")
	}

	if len(out) != len(in) {
		t.Fatalf("len: got %d want %d", len(out), len(in))
	}
	for k, v := range in {
		got, ok := out[k]
		if !ok {
			t.Errorf("missing key %d", k)
			continue
		}
		if !bytes.Equal(got, v) {
			t.Errorf("key %d: got %q want %q", k, got, v)
		}
	}
}

func TestZAP_SendRecvBytesSliceMap(t *testing.T) {
	comm0, comm1, cleanup := twoPartyZAP(t)
	defer cleanup()

	in := map[int][][]byte{
		0: {[]byte("seed-0-a"), []byte("seed-0-b")},
		1: {[]byte("seed-1-a"), []byte("seed-1-b"), []byte("seed-1-c")},
	}

	var out map[int][][]byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out = comm1.RecvBytesSliceMap(nil, 0)
	}()
	comm0.SendBytesSliceMap(nil, 1, in)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ZAP bytes-slice-map recv timed out")
	}

	if len(out) != len(in) {
		t.Fatalf("len: got %d want %d", len(out), len(in))
	}
	for k, vs := range in {
		gotVs, ok := out[k]
		if !ok {
			t.Errorf("missing key %d", k)
			continue
		}
		if len(gotVs) != len(vs) {
			t.Errorf("key %d: len got %d want %d", k, len(gotVs), len(vs))
			continue
		}
		for i := range vs {
			if !bytes.Equal(gotVs[i], vs[i]) {
				t.Errorf("key %d slice %d: got %q want %q", k, i, gotVs[i], vs[i])
			}
		}
	}
}

// TestZAP_RoundtripPreservesLatticeBytes asserts the byte-equal-on-
// semantic-wire invariant: the bytes Corona participants compute
// against (the lattice serialization) are identical to what a direct
// in-memory WriteTo/ReadFrom would produce. The ZAP framing is purely
// envelope.
func TestZAP_RoundtripPreservesLatticeBytes(t *testing.T) {
	r, _ := ring.NewRing(256, []uint64{8380417})
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	v := make(structs.Vector[ring.Poly], 4)
	for i := range v {
		v[i] = sampler.ReadNew()
	}

	// Expected bytes: pure lattice serialization.
	var expected bytes.Buffer
	if _, err := v.WriteTo(&expected); err != nil {
		t.Fatalf("expected WriteTo: %v", err)
	}

	comm0, comm1, cleanup := twoPartyZAP(t)
	defer cleanup()

	var received structs.Vector[ring.Poly]
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		received = comm1.RecvVector(nil, 0, len(v))
	}()
	comm0.SendVector(nil, 1, v)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ZAP roundtrip recv timed out")
	}

	// The received vector must serialize back to byte-equal output.
	var actual bytes.Buffer
	if _, err := received.WriteTo(&actual); err != nil {
		t.Fatalf("actual WriteTo: %v", err)
	}
	if !bytes.Equal(expected.Bytes(), actual.Bytes()) {
		t.Fatalf("lattice serialization differs across ZAP transport (len exp=%d got=%d)", expected.Len(), actual.Len())
	}
}

// BenchmarkSendRecvVector_ZAP measures the round-trip cost of the ZAP
// transport for a representative Corona payload.
func BenchmarkSendRecvVector_ZAP(b *testing.B) {
	port0, port1 := pickPort(b), pickPort(b)
	silent := newSilentLogger()
	comm0, err := NewP2PComm(0, port0, true, silent)
	if err != nil {
		b.Fatalf("NewP2PComm 0: %v", err)
	}
	defer comm0.Close()
	comm1, err := NewP2PComm(1, port1, true, silent)
	if err != nil {
		b.Fatalf("NewP2PComm 1: %v", err)
	}
	defer comm1.Close()
	if err := comm0.Connect(1, fmt.Sprintf("127.0.0.1:%d", port1)); err != nil {
		b.Fatalf("connect: %v", err)
	}
	comm1.AcceptPeer(0)
	time.Sleep(100 * time.Millisecond)

	r, _ := ring.NewRing(256, []uint64{8380417})
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	v := make(structs.Vector[ring.Poly], 8)
	for i := range v {
		v[i] = sampler.ReadNew()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		done := make(chan struct{})
		go func() {
			_ = comm1.RecvVector(nil, 0, len(v))
			close(done)
		}()
		comm0.SendVector(nil, 1, v)
		<-done
	}
}

func pickPort(b *testing.B) int {
	b.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("pickPort: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

// BenchmarkSendRecvVector_BareTCPPipe is the cheap synchronous in-
// memory baseline. net.Pipe has no TCP-stack overhead — it just hands
// the bytes between goroutines through a mutex. Useful as a floor on
// the lattice-serialization cost alone.
func BenchmarkSendRecvVector_BareTCPPipe(b *testing.B) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	comm0 := &P2PComm{Rank: 0, Socks: map[int]*net.Conn{1: &client}}
	comm1 := &P2PComm{Rank: 1, Socks: map[int]*net.Conn{0: &server}}

	r, _ := ring.NewRing(256, []uint64{8380417})
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	v := make(structs.Vector[ring.Poly], 8)
	for i := range v {
		v[i] = sampler.ReadNew()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		done := make(chan struct{})
		go func() {
			reader := bufioNewReader(server)
			_ = comm1.RecvVector(reader, 0, len(v))
			close(done)
		}()
		writer := bufioNewWriter(client)
		comm0.SendVector(writer, 1, v)
		<-done
	}
}

// BenchmarkSendRecvVector_BareTCPLoopback is the apples-to-apples
// baseline for the ZAP bench: real TCP on the loopback interface
// using the pre-migration manual-length-prefix code path
// (SendVector via writer.Flush over a real net.TCPConn).
func BenchmarkSendRecvVector_BareTCPLoopback(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		connCh <- c
	}()
	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()
	serverConn := <-connCh
	defer serverConn.Close()

	var client net.Conn = clientConn
	var server net.Conn = serverConn

	comm0 := &P2PComm{Rank: 0, Socks: map[int]*net.Conn{1: &client}}
	comm1 := &P2PComm{Rank: 1, Socks: map[int]*net.Conn{0: &server}}

	r, _ := ring.NewRing(256, []uint64{8380417})
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	v := make(structs.Vector[ring.Poly], 8)
	for i := range v {
		v[i] = sampler.ReadNew()
	}

	reader := bufioNewReader(server)
	writer := bufioNewWriter(client)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		done := make(chan struct{})
		go func() {
			_ = comm1.RecvVector(reader, 0, len(v))
			close(done)
		}()
		comm0.SendVector(writer, 1, v)
		<-done
	}
}
