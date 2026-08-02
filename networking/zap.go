// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package networking provides the Corona ceremony transport layer.
//
// Wire model. Every Corona send (vector, matrix, byte-slice, byte-map,
// byte-slice-map) is encoded to bytes via the lattice WriteTo/ReadFrom
// routines (vector.go and friends in luxfi/lattice/v7/utils/structs).
// Those bytes are byte-equal regardless of transport — that is the
// "semantic-level wire" Corona participants compute against.
//
// Pre-migration the bytes were length-prefixed and shipped raw over a
// bare TCP socket. Post-migration they ride inside a ZAP message body
// over zap.Node, which gives us:
//
//   - One framed transport (no manual binary.BigEndian length-prefix
//     loops, no zero-copy regressions on every recv).
//   - Multi-transport (TCP today, QUIC tomorrow with an unchanged
//     P2PComm API).
//   - mDNS discovery and ConnectDirect for tests and topology-known
//     deployments.
//
// One ZAP message == one logical Corona send. The receiver dequeues one
// message and parses the lattice object from its body. The lattice
// length tags inside the body are preserved verbatim.
package networking

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/luxfi/zap"
)

// CoronaMsgType is the ZAP message-type slot used by Corona's ceremony
// transport. It lives inside this package as an internal kind-byte
// namespace — no LP allocation needed because the only sender and
// receiver are Corona networking peers talking to each other.
//
// ZAP encodes the message type in the high byte of the 16-bit Flags
// field (msgType == Flags >> 8), so the kind-byte range is 0..255.
// 0xCE reads "Corona Ceremony"; we own this slot inside the
// corona/networking package only.
//
// All Corona traffic uses this single type because the call sequence
// on each side determines round semantics (R1 share, R2 nonce-
// commitment, R3 signature share, abort) — exactly as it did over
// bare TCP.
const CoronaMsgType uint8 = 0xCE

// CoronaServiceType is the mDNS service tag for Corona ceremony peers.
// Tests and unit fixtures set NodeConfig.NoDiscovery=true and use
// ConnectDirect with an explicit address; production deployments can
// flip this on for zero-config discovery on a LAN.
const CoronaServiceType = "_corona._tcp"

// peerStream is the receive side of one Corona peer relationship.
// Send goes through zap.Node.Send; receive blocks on a FIFO of message
// bodies pushed by the ZAP handler.
type peerStream struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte
	closed bool
	peerID string // ZAP peer ID (string-form of integer party ID)
}

func newPeerStream() *peerStream {
	ps := &peerStream{}
	ps.cond = sync.NewCond(&ps.mu)
	return ps
}

// push appends a message body to the queue and wakes one waiter.
func (ps *peerStream) push(body []byte) {
	ps.mu.Lock()
	if ps.closed {
		ps.mu.Unlock()
		return
	}
	ps.queue = append(ps.queue, body)
	ps.cond.Signal()
	ps.mu.Unlock()
}

// pop dequeues the next message body, blocking if empty. Returns
// io.EOF if the stream is closed and the queue is drained.
func (ps *peerStream) pop() ([]byte, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for len(ps.queue) == 0 {
		if ps.closed {
			return nil, io.EOF
		}
		ps.cond.Wait()
	}
	body := ps.queue[0]
	ps.queue = ps.queue[1:]
	return body, nil
}

// close stops further pushes and wakes all waiters with io.EOF.
func (ps *peerStream) close() {
	ps.mu.Lock()
	ps.closed = true
	ps.cond.Broadcast()
	ps.mu.Unlock()
}

// zapNode is the runtime backing a P2PComm. One per local party.
type zapNode struct {
	node    *zap.Node
	logger  *slog.Logger
	streams map[int]*peerStream // dst rank -> recv queue
	peers   map[int]string      // rank -> zap NodeID
	mu      sync.RWMutex
}

// peerID encodes an integer party rank as a ZAP NodeID. Stable,
// deterministic, easy to reverse for handler dispatch.
func peerID(rank int) string {
	return fmt.Sprintf("corona-%d", rank)
}

// rankFromPeerID is the inverse of peerID. Returns -1 if the peer
// is not a corona party (e.g. a stray mDNS neighbor on the LAN).
func rankFromPeerID(id string) int {
	var rank int
	if _, err := fmt.Sscanf(id, "corona-%d", &rank); err != nil {
		return -1
	}
	return rank
}

// newZapNode creates a ZAP node bound to the given port. The caller is
// responsible for Start() and Stop().
func newZapNode(rank int, port int, noDiscovery bool, logger *slog.Logger) *zapNode {
	if logger == nil {
		logger = slog.Default()
	}
	zn := &zapNode{
		logger:  logger,
		streams: make(map[int]*peerStream),
		peers:   make(map[int]string),
	}
	zn.node = zap.NewNode(zap.NodeConfig{
		NodeID:      peerID(rank),
		ServiceType: CoronaServiceType,
		Port:        port,
		NoDiscovery: noDiscovery,
		Logger:      logger,
	})
	zn.node.Handle(uint16(CoronaMsgType), zn.handleIncoming)
	return zn
}

// getOrCreateStream returns the recv queue for src, creating one on
// first use. Caller must hold no locks; the function locks internally.
func (zn *zapNode) getOrCreateStream(src int) *peerStream {
	zn.mu.RLock()
	ps, ok := zn.streams[src]
	zn.mu.RUnlock()
	if ok {
		return ps
	}
	zn.mu.Lock()
	defer zn.mu.Unlock()
	if ps, ok := zn.streams[src]; ok {
		return ps
	}
	ps = newPeerStream()
	ps.peerID = peerID(src)
	zn.streams[src] = ps
	return ps
}

// handleIncoming is the ZAP handler for Corona ceremony messages. It
// resolves the sender's rank from peerID and pushes the message body
// into that rank's receive queue.
//
// The handler returns (nil, nil): Corona uses one-way sends, not
// request/response correlated calls. The lattice encoding is
// self-delimiting inside the message body.
func (zn *zapNode) handleIncoming(_ context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	rank := rankFromPeerID(from)
	if rank < 0 {
		// Foreign peer — drop silently. Production should not see this
		// because the service-type is Corona-specific; tests using
		// ConnectDirect always wire the right node IDs.
		return nil, nil
	}
	// Copy the body. The pooled bufRef behind msg.Bytes() will be
	// released as soon as the handler returns, but the queue can hold
	// the body until any time the receiver dequeues.
	body := append([]byte(nil), msg.Bytes()...)
	zn.getOrCreateStream(rank).push(body)
	return nil, nil
}

// send wraps body in a ZAP message and ships it to the destination
// rank's peer via zap.Node.Send. The message-type lives in the top
// byte of Flags (Flags >> 8 == CoronaMsgType).
func (zn *zapNode) send(ctx context.Context, dst int, body []byte) error {
	zn.mu.RLock()
	peer, ok := zn.peers[dst]
	zn.mu.RUnlock()
	if !ok {
		return fmt.Errorf("corona: no peer registered for rank %d", dst)
	}
	// Build a single-bytes-field ZAP message carrying the lattice
	// payload verbatim. Flags top byte = CoronaMsgType for dispatch.
	// We use SetBytes (variable-length tail) — the body fits there
	// regardless of size, and on the receive side we read it back as
	// a Bytes field with the same offset.
	b := zap.NewBuilder(len(body) + zap.HeaderSize + 32)
	obj := b.StartObject(8) // tail pointer: 4-byte offset + 4-byte length
	obj.SetBytes(0, body)
	obj.FinishAsRoot()
	frame := b.FinishWithFlags(uint16(CoronaMsgType) << 8)
	parsed, err := zap.Parse(frame)
	if err != nil {
		return fmt.Errorf("corona: build zap frame: %w", err)
	}
	return zn.node.Send(ctx, peer, parsed)
}

// recvBody dequeues the next message from src and returns the raw
// lattice-serialized body. Blocks until one arrives or the stream
// closes (io.EOF).
//
// One copy: the handler stashed the full ZAP frame in the queue; we
// parse it here and return a slice into that frame. Because the
// queue-owned frame outlives this call (it's freed when GC reclaims
// the queue entry), the returned slice is safe to hold.
func (zn *zapNode) recvBody(src int) ([]byte, error) {
	frame, err := zn.getOrCreateStream(src).pop()
	if err != nil {
		return nil, err
	}
	msg, err := zap.Parse(frame)
	if err != nil {
		return nil, fmt.Errorf("corona: parse zap frame: %w", err)
	}
	body := msg.Root().Bytes(0)
	if body == nil {
		return nil, errors.New("corona: empty body in ZAP message")
	}
	return body, nil
}

// registerPeer binds a party rank to its ZAP peer ID. Called after a
// successful Connect or Listen handshake for the (rank, addr) pair.
func (zn *zapNode) registerPeer(rank int) {
	zn.mu.Lock()
	zn.peers[rank] = peerID(rank)
	zn.mu.Unlock()
}

// close shuts down the ZAP node and all peer streams.
func (zn *zapNode) close() {
	zn.mu.Lock()
	for _, ps := range zn.streams {
		ps.close()
	}
	zn.mu.Unlock()
	if zn.node != nil {
		zn.node.Stop()
	}
}

// CalculatePortOffset is the historical convention used by Corona's
// EstablishConnections to derive a unique port per (partyA, partyB)
// pair. Kept for callers that still drive deployment topology with
// a hard-coded port grid.
//
// CalculatePortOffset(a, b) == CalculatePortOffset(b, a) by design —
// both sides of a pair need to agree on the same port without
// negotiating.
func CalculatePortOffset(partyID, otherID int) int {
	if partyID < otherID {
		return partyID*100 + otherID
	}
	return otherID*100 + partyID
}
