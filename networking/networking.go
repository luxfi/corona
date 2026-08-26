// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package networking

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/luxfi/corona/wire"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// P2PComm is the Corona ceremony communicator. Each party holds one
// P2PComm which it uses to send Vector/Matrix/byte-bag payloads to
// every other party in the round.
//
// Transport is ZAP (luxfi/zap) — every Send* call wraps the lattice-
// serialized bytes in a single ZAP message and ships it via zap.Node;
// every Recv* call dequeues the next ZAP message from the peer's
// receive queue and reads the lattice object from its body.
//
// The lattice serialization (uint64 length + element bytes) inside the
// message body is byte-equal to the pre-migration bare-TCP encoding —
// the protocol bytes Corona participants compute against did not move.
type P2PComm struct {
	Rank int

	// Socks is retained for backward compatibility with hand-written
	// fixtures that wire net.Pipe pairs directly into the comm. New
	// code should not touch this map; use the ZAP-backed transport
	// (NewP2PComm / Connect / Listen) instead.
	//
	// When Socks contains a *net.Conn for a peer, Send*/Recv* fall back
	// to the legacy in-memory pipe path so existing unit tests keep
	// passing without modification.
	Socks map[int]*net.Conn

	mu     sync.Mutex
	node   *zapNode
	logger *slog.Logger
}

// NewP2PComm creates a Corona communicator backed by a ZAP node bound
// to the given port. Set noDiscovery=true in tests or topology-known
// deployments and supply peer addresses via Connect.
func NewP2PComm(rank int, port int, noDiscovery bool, logger *slog.Logger) (*P2PComm, error) {
	if logger == nil {
		logger = slog.Default()
	}
	zn := newZapNode(rank, port, noDiscovery, logger)
	if err := zn.node.Start(); err != nil {
		return nil, fmt.Errorf("corona: start zap node: %w", err)
	}
	return &P2PComm{
		Rank:   rank,
		Socks:  make(map[int]*net.Conn),
		node:   zn,
		logger: logger,
	}, nil
}

// Connect dials the peer at addr and binds it to the given rank. Use
// when topology is known up-front (the historical EstablishConnections
// path); when mDNS discovery is enabled, peers are picked up
// automatically and Connect is unnecessary.
func (comm *P2PComm) Connect(rank int, addr string) error {
	if comm.node == nil {
		return fmt.Errorf("corona: P2PComm has no zap node (call NewP2PComm)")
	}
	// Retry: peers may not have bound their listener yet.
	var lastErr error
	for i := 0; i < 10; i++ {
		if err := comm.node.node.ConnectDirect(addr); err == nil {
			comm.node.registerPeer(rank)
			return nil
		} else {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
		}
	}
	return fmt.Errorf("corona: connect rank=%d addr=%s: %w", rank, addr, lastErr)
}

// AcceptPeer marks rank as a known peer that will dial us. mDNS-less
// deployments where the lower-rank side dials and the higher-rank side
// listens (Corona's historical convention) use this to pre-register
// the incoming peer so Send* knows the ZAP NodeID to address.
func (comm *P2PComm) AcceptPeer(rank int) {
	if comm.node != nil {
		comm.node.registerPeer(rank)
	}
}

// Close releases all transport resources.
func (comm *P2PComm) Close() error {
	if comm.node != nil {
		comm.node.close()
	}
	comm.mu.Lock()
	defer comm.mu.Unlock()
	for _, sock := range comm.Socks {
		if sock != nil && *sock != nil {
			_ = (*sock).Close()
		}
	}
	return nil
}

// SetSock is retained for legacy hand-written fixtures.
func (comm *P2PComm) SetSock(key int, conn *net.Conn) {
	comm.mu.Lock()
	defer comm.mu.Unlock()
	comm.Socks[key] = conn
}

// GetSock is retained for legacy hand-written fixtures.
func (comm *P2PComm) GetSock(key int) *net.Conn {
	comm.mu.Lock()
	defer comm.mu.Unlock()
	return comm.Socks[key]
}

// hasLegacySock reports whether the (legacy) Socks map has a live conn
// for the given rank. When true the Send*/Recv* methods route through
// the bufio.Writer/Reader the caller supplies (test compatibility);
// when false they go through the ZAP node.
func (comm *P2PComm) hasLegacySock(rank int) bool {
	comm.mu.Lock()
	defer comm.mu.Unlock()
	sock, ok := comm.Socks[rank]
	return ok && sock != nil && *sock != nil
}

// ---------------------------------------------------------------------
// Send / Recv primitives.
//
// Every method has two paths:
//
//   1. Legacy direct-conn path. If hasLegacySock(dst) is true (i.e.
//      a *net.Conn was wired in via SetSock), the call writes/reads
//      to the supplied bufio.Writer/Reader directly. This keeps the
//      net.Pipe-based unit tests in networking_test.go working without
//      modification.
//
//   2. ZAP path. Otherwise the call serializes the lattice object to
//      an in-memory bytes.Buffer, ships the bytes as one ZAP message
//      to the peer, and on the receive side dequeues the next ZAP
//      message from the per-peer FIFO and parses the lattice object
//      from its body.
//
// The lattice serialization itself (vector.go/matrix.go WriteTo/
// ReadFrom in luxfi/lattice) is identical across both paths — the
// "semantic-level wire" the ceremony computes against is byte-equal.
// ---------------------------------------------------------------------

// SendVector serializes a lattice vector to bytes and ships it to dst.
// writer is honored when present (legacy path); otherwise the ZAP node
// is used.
func (comm *P2PComm) SendVector(writer *bufio.Writer, dst int, msg structs.Vector[ring.Poly]) error {
	body, err := marshalTo(msg)
	if err != nil {
		return fmt.Errorf("corona/net: encode vector for %d: %w", dst, err)
	}
	return comm.deliver(writer, dst, body)
}

// RecvVector reads a lattice vector of the given length from src.
func (comm *P2PComm) RecvVector(reader *bufio.Reader, src int, length int) (structs.Vector[ring.Poly], error) {
	if comm.streaming(reader, src) {
		vec := make(structs.Vector[ring.Poly], length)
		if _, err := vec.ReadFrom(reader); err != nil {
			return nil, fmt.Errorf("corona/net: decode vector from %d: %w", src, err)
		}
		return vec, nil
	}
	body, err := comm.collect(src)
	if err != nil {
		return nil, fmt.Errorf("corona/net: read vector from %d: %w", src, err)
	}
	if err := wire.ValidateVectorPolyFrame(body); err != nil {
		return nil, fmt.Errorf("corona/net: vector from %d: %w", src, err)
	}
	vec := make(structs.Vector[ring.Poly], length)
	if _, err := vec.ReadFrom(bufio.NewReader(bytes.NewReader(body))); err != nil {
		return nil, fmt.Errorf("corona/net: decode vector from %d: %w", src, err)
	}
	return vec, nil
}

// SendMatrix ships a lattice matrix to dst.
func (comm *P2PComm) SendMatrix(writer *bufio.Writer, dst int, msg structs.Matrix[ring.Poly]) error {
	body, err := marshalTo(msg)
	if err != nil {
		return fmt.Errorf("corona/net: encode matrix for %d: %w", dst, err)
	}
	return comm.deliver(writer, dst, body)
}

// RecvMatrix reads a lattice matrix of the given row count from src.
func (comm *P2PComm) RecvMatrix(reader *bufio.Reader, src int, length int) (structs.Matrix[ring.Poly], error) {
	if comm.streaming(reader, src) {
		m := make(structs.Matrix[ring.Poly], length)
		if _, err := m.ReadFrom(reader); err != nil {
			return nil, fmt.Errorf("corona/net: decode matrix from %d: %w", src, err)
		}
		return m, nil
	}
	body, err := comm.collect(src)
	if err != nil {
		return nil, fmt.Errorf("corona/net: read matrix from %d: %w", src, err)
	}
	if err := wire.ValidateMatrixPolyFrame(body); err != nil {
		return nil, fmt.Errorf("corona/net: matrix from %d: %w", src, err)
	}
	m := make(structs.Matrix[ring.Poly], length)
	if _, err := m.ReadFrom(bufio.NewReader(bytes.NewReader(body))); err != nil {
		return nil, fmt.Errorf("corona/net: decode matrix from %d: %w", src, err)
	}
	return m, nil
}

// SendBytesSlice ships a slice of byte-slices to dst with explicit
// length tags. Wire layout: uint32 numSlices, then for each slice
// uint32 length + slice bytes.
func (comm *P2PComm) SendBytesSlice(writer *bufio.Writer, dst int, data [][]byte) error {
	return comm.deliver(writer, dst, encodeBytesSlice(data))
}

// RecvBytesSlice reads a length-prefixed slice-of-slices from src.
func (comm *P2PComm) RecvBytesSlice(reader *bufio.Reader, src int) ([][]byte, error) {
	if comm.streaming(reader, src) {
		return decodeBytesSlice(reader), nil
	}
	body, err := comm.collect(src)
	if err != nil {
		return nil, fmt.Errorf("corona/net: read bytes slice from %d: %w", src, err)
	}
	return decodeBytesSlice(bufio.NewReader(bytes.NewReader(body))), nil
}

// SendBytesMap ships a map<int,[]byte> to dst.
func (comm *P2PComm) SendBytesMap(writer *bufio.Writer, dst int, data map[int][]byte) error {
	return comm.deliver(writer, dst, encodeBytesMap(data))
}

// RecvBytesMap reads a map<int,[]byte> from src.
func (comm *P2PComm) RecvBytesMap(reader *bufio.Reader, src int) (map[int][]byte, error) {
	if comm.streaming(reader, src) {
		return decodeBytesMap(reader), nil
	}
	body, err := comm.collect(src)
	if err != nil {
		return nil, fmt.Errorf("corona/net: read bytes map from %d: %w", src, err)
	}
	return decodeBytesMap(bufio.NewReader(bytes.NewReader(body))), nil
}

// SendBytesSliceMap ships a map<int,[][]byte> to dst.
func (comm *P2PComm) SendBytesSliceMap(writer *bufio.Writer, dst int, data map[int][][]byte) error {
	return comm.deliver(writer, dst, encodeBytesSliceMap(data))
}

// RecvBytesSliceMap reads a map<int,[][]byte> from src.
func (comm *P2PComm) RecvBytesSliceMap(reader *bufio.Reader, src int) (map[int][][]byte, error) {
	if comm.streaming(reader, src) {
		return decodeBytesSliceMap(reader), nil
	}
	body, err := comm.collect(src)
	if err != nil {
		return nil, fmt.Errorf("corona/net: read bytes-slice map from %d: %w", src, err)
	}
	return decodeBytesSliceMap(bufio.NewReader(bytes.NewReader(body))), nil
}

// marshalTo renders a lattice value to the bytes that go on the wire.
func marshalTo(msg io.WriterTo) ([]byte, error) {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	if _, err := msg.WriteTo(bw); err != nil {
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// deliver is the one way a body reaches a peer: the legacy socket when one is
// still held for that rank, the ZAP node otherwise.
func (comm *P2PComm) deliver(writer *bufio.Writer, dst int, body []byte) error {
	if writer != nil && comm.hasLegacySock(dst) {
		if _, err := writer.Write(body); err != nil {
			return fmt.Errorf("corona/net: write to %d: %w", dst, err)
		}
		if err := writer.Flush(); err != nil {
			return fmt.Errorf("corona/net: flush to %d: %w", dst, err)
		}
		return nil
	}
	if err := comm.node.send(context.Background(), dst, body); err != nil {
		return fmt.Errorf("corona/net: send to %d: %w", dst, err)
	}
	return nil
}

// streaming reports whether this peer is read from a socket rather than as
// discrete messages. A stream has no message boundary to read up to, so a value
// is decoded straight from it; a discrete body is walked before it is decoded.
func (comm *P2PComm) streaming(reader *bufio.Reader, src int) bool {
	return reader != nil && comm.hasLegacySock(src)
}

// collect takes one discrete message from a peer as bytes rather than as a
// decoded value. That is the point: a peer writes the counts inside these
// bytes and the lattice decoder sizes its work from them, so the frame is
// walked before anything decodes it.
func (comm *P2PComm) collect(src int) ([]byte, error) {
	return comm.node.recvBody(src)
}

// ---------------------------------------------------------------------
// Byte-bag wire format.
//
// These encoders/decoders preserve the historical wire layout used by
// Corona over bare-TCP: big-endian uint32 counts and lengths followed
// by raw byte runs. They are now used inside ZAP message bodies, so
// the ZAP frame contains a verbatim copy of the legacy bytes.
// ---------------------------------------------------------------------

func encodeBytesSlice(data [][]byte) []byte {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	numSlices := uint32(len(data))
	if err := binary.Write(bw, binary.BigEndian, numSlices); err != nil {
		log.Fatalf("Failed to write number of slices: %v", err)
	}
	for _, slice := range data {
		length := uint32(len(slice))
		if err := binary.Write(bw, binary.BigEndian, length); err != nil {
			log.Fatalf("Failed to write slice length: %v", err)
		}
		if _, err := bw.Write(slice); err != nil {
			log.Fatalf("Failed to write slice data: %v", err)
		}
	}
	if err := bw.Flush(); err != nil {
		log.Fatalf("Failed to flush bytes-slice buffer: %v", err)
	}
	return buf.Bytes()
}

func decodeBytesSlice(r *bufio.Reader) [][]byte {
	var numSlices uint32
	if err := binary.Read(r, binary.BigEndian, &numSlices); err != nil {
		log.Fatalf("Failed to read number of slices: %v", err)
	}
	data := make([][]byte, numSlices)
	for i := uint32(0); i < numSlices; i++ {
		var length uint32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			log.Fatalf("Failed to read slice length: %v", err)
		}
		slice := make([]byte, length)
		bytesRead := 0
		for bytesRead < int(length) {
			n, err := r.Read(slice[bytesRead:])
			if err != nil {
				log.Fatalf("Failed to read slice data: %v", err)
			}
			bytesRead += n
		}
		data[i] = slice
	}
	return data
}

func encodeBytesMap(data map[int][]byte) []byte {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	numEntries := uint32(len(data))
	if err := binary.Write(bw, binary.BigEndian, numEntries); err != nil {
		log.Fatalf("Failed to write number of map entries: %v", err)
	}
	for key, value := range data {
		if err := binary.Write(bw, binary.BigEndian, int32(key)); err != nil {
			log.Fatalf("Failed to write map key: %v", err)
		}
		length := uint32(len(value))
		if err := binary.Write(bw, binary.BigEndian, length); err != nil {
			log.Fatalf("Failed to write value length: %v", err)
		}
		if _, err := bw.Write(value); err != nil {
			log.Fatalf("Failed to write value data: %v", err)
		}
	}
	if err := bw.Flush(); err != nil {
		log.Fatalf("Failed to flush bytes-map buffer: %v", err)
	}
	return buf.Bytes()
}

func decodeBytesMap(r *bufio.Reader) map[int][]byte {
	var numEntries uint32
	if err := binary.Read(r, binary.BigEndian, &numEntries); err != nil {
		log.Fatalf("Failed to read number of map entries: %v", err)
	}
	data := make(map[int][]byte, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		var key int32
		if err := binary.Read(r, binary.BigEndian, &key); err != nil {
			log.Fatalf("Failed to read map key: %v", err)
		}
		var length uint32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			log.Fatalf("Failed to read value length: %v", err)
		}
		value := make([]byte, length)
		bytesRead := 0
		for bytesRead < int(length) {
			n, err := r.Read(value[bytesRead:])
			if err != nil {
				log.Fatalf("Failed to read value data: %v", err)
			}
			bytesRead += n
		}
		data[int(key)] = value
	}
	return data
}

func encodeBytesSliceMap(data map[int][][]byte) []byte {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	numEntries := uint32(len(data))
	if err := binary.Write(bw, binary.BigEndian, numEntries); err != nil {
		log.Fatalf("Failed to write number of map entries: %v", err)
	}
	for key, value := range data {
		if err := binary.Write(bw, binary.BigEndian, int32(key)); err != nil {
			log.Fatalf("Failed to write map key: %v", err)
		}
		numSlices := uint32(len(value))
		if err := binary.Write(bw, binary.BigEndian, numSlices); err != nil {
			log.Fatalf("Failed to write number of slices: %v", err)
		}
		for _, slice := range value {
			length := uint32(len(slice))
			if err := binary.Write(bw, binary.BigEndian, length); err != nil {
				log.Fatalf("Failed to write slice length: %v", err)
			}
			if _, err := bw.Write(slice); err != nil {
				log.Fatalf("Failed to write slice data: %v", err)
			}
		}
	}
	if err := bw.Flush(); err != nil {
		log.Fatalf("Failed to flush bytes-slice map buffer: %v", err)
	}
	return buf.Bytes()
}

func decodeBytesSliceMap(r *bufio.Reader) map[int][][]byte {
	var numEntries uint32
	if err := binary.Read(r, binary.BigEndian, &numEntries); err != nil {
		log.Fatalf("Failed to read number of map entries: %v", err)
	}
	data := make(map[int][][]byte, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		var key int32
		if err := binary.Read(r, binary.BigEndian, &key); err != nil {
			log.Fatalf("Failed to read map key: %v", err)
		}
		var numSlices uint32
		if err := binary.Read(r, binary.BigEndian, &numSlices); err != nil {
			log.Fatalf("Failed to read number of slices: %v", err)
		}
		slices := make([][]byte, numSlices)
		for j := uint32(0); j < numSlices; j++ {
			var length uint32
			if err := binary.Read(r, binary.BigEndian, &length); err != nil {
				log.Fatalf("Failed to read slice length: %v", err)
			}
			slice := make([]byte, length)
			bytesRead := 0
			for bytesRead < int(length) {
				n, err := r.Read(slice[bytesRead:])
				if err != nil {
					log.Fatalf("Failed to read slice data: %v", err)
				}
				bytesRead += n
			}
			slices[j] = slice
		}
		data[int(key)] = slices
	}
	return data
}

// ---------------------------------------------------------------------
// Topology helpers — the historical EstablishConnections path lived
// here. The new ZAP-backed equivalent takes a peer address map from
// the caller rather than hard-coding EC2 IPs.
// ---------------------------------------------------------------------

// EstablishConnectionsZAP wires all (partyID, otherID) pairs over the
// ZAP transport. peerAddrs[otherID] must be the "host:port" of the
// peer's listening socket. The lower-rank side dials, the higher-rank
// side listens — the historical Corona convention preserved.
func (comm *P2PComm) EstablishConnectionsZAP(partyID, totalParties int, peerAddrs map[int]string) error {
	var wg sync.WaitGroup
	errCh := make(chan error, totalParties)
	for otherID := 0; otherID < totalParties; otherID++ {
		if otherID == partyID {
			continue
		}
		wg.Add(1)
		go func(otherID int) {
			defer wg.Done()
			if partyID < otherID {
				// We listen — peer will dial us. Pre-register so
				// Send* knows the peer's NodeID.
				comm.AcceptPeer(otherID)
			} else {
				addr, ok := peerAddrs[otherID]
				if !ok {
					errCh <- fmt.Errorf("corona: no address for peer rank %d", otherID)
					return
				}
				if err := comm.Connect(otherID, addr); err != nil {
					errCh <- err
				}
			}
		}(otherID)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}
