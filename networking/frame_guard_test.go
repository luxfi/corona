// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package networking

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/luxfi/corona/wire"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func le(n uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return b[:]
}

// TestAFrameIsWalkedBeforeItIsDecoded. A peer writes the counts inside a
// lattice frame, and the decoder sizes its work from them: a frame naming far
// more than it carries costs the receiver time proportional to what it named
// rather than to what it sent. Walking the frame first bounds that to the
// bytes actually present.
func TestAFrameIsWalkedBeforeItIsDecoded(t *testing.T) {
	// One poly claiming 2^40 coefficients, with none behind it.
	frame := append(append(le(1), le(1)...), le(1<<40)...)

	walked := time.Now()
	err := wire.ValidateVectorPolyFrame(frame)
	walkCost := time.Since(walked)
	if err == nil {
		t.Fatal("a frame naming more than it carries was accepted")
	}

	decoded := time.Now()
	vec := make(structs.Vector[ring.Poly], 1)
	_, _ = vec.ReadFrom(bufio.NewReader(bytes.NewReader(frame)))
	decodeCost := time.Since(decoded)

	t.Logf("walk %v, decode %v, from %d bytes", walkCost, decodeCost, len(frame))
	if walkCost >= decodeCost {
		t.Fatalf("walking cost %v and decoding cost %v — the walk is meant to be the cheap way to find this out",
			walkCost, decodeCost)
	}
}

// TestRecvRefusesAFrameThatOutrunsItsBytes drives a real peer connection: one
// party puts a body on the wire that names far more than it carries, and the
// other has to refuse it and stay up. Sent raw rather than through SendVector,
// because SendVector only ever writes frames that are honest about their size.
func TestRecvRefusesAFrameThatOutrunsItsBytes(t *testing.T) {
	comm0, comm1, cleanup := twoPartyZAP(t)
	defer cleanup()

	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"a vector naming 2^40 polys", le(1 << 40)},
		{"a poly naming 2^40 coefficients", append(append(le(1), le(1)...), le(1<<40)...)},
		{"a count with no room for its own bytes", []byte{1, 2, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				recvErr error
				done    = make(chan struct{})
			)
			go func() {
				_, recvErr = comm1.RecvVector(nil, 0, 1)
				close(done)
			}()
			if err := comm0.node.send(context.Background(), 1, tc.frame); err != nil {
				t.Fatalf("send raw frame: %v", err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the receiver never answered; a frame naming 2^40 should be refused at once")
			}
			if recvErr == nil {
				t.Fatal("a frame naming more than it carries was accepted from a peer")
			}
		})
	}
}
