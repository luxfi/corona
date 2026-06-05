// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package networking

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"log/slog"
	"net"
	"sync"
	"time"

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
func (comm *P2PComm) SendVector(writer *bufio.Writer, dst int, msg structs.Vector[ring.Poly]) {
	if writer != nil && comm.hasLegacySock(dst) {
		if _, err := msg.WriteTo(writer); err != nil {
			log.Fatalf("Failed to write vector: %v", err)
		}
		if err := writer.Flush(); err != nil {
			log.Fatalf("Failed to flush writer: %v", err)
		}
		return
	}
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	if _, err := msg.WriteTo(bw); err != nil {
		log.Fatalf("Failed to write vector: %v", err)
	}
	if err := bw.Flush(); err != nil {
		log.Fatalf("Failed to flush vector buffer: %v", err)
	}
	if err := comm.node.send(context.Background(), dst, buf.Bytes()); err != nil {
		log.Fatalf("Failed to send vector to %d: %v", dst, err)
	}
}

// RecvVector reads a lattice vector of the given length from src.
func (comm *P2PComm) RecvVector(reader *bufio.Reader, src int, length int) structs.Vector[ring.Poly] {
	if reader != nil && comm.hasLegacySock(src) {
		vec := make(structs.Vector[ring.Poly], length)
		if _, err := vec.ReadFrom(reader); err != nil {
			log.Fatalf("Failed to read vector: %v", err)
		}
		return vec
	}
	body, err := comm.node.recvBody(src)
	if err != nil {
		log.Fatalf("Failed to recv vector from %d: %v", src, err)
	}
	vec := make(structs.Vector[ring.Poly], length)
	if _, err := vec.ReadFrom(bufio.NewReader(bytes.NewReader(body))); err != nil {
		log.Fatalf("Failed to read vector: %v", err)
	}
	return vec
}

// SendMatrix serializes a lattice matrix to bytes and ships it to dst.
func (comm *P2PComm) SendMatrix(writer *bufio.Writer, dst int, msg structs.Matrix[ring.Poly]) {
	if writer != nil && comm.hasLegacySock(dst) {
		if _, err := msg.WriteTo(writer); err != nil {
			log.Fatalf("Error sending matrix: %v", err)
		}
		if err := writer.Flush(); err != nil {
			log.Fatalf("Failed to flush writer: %v", err)
		}
		return
	}
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	if _, err := msg.WriteTo(bw); err != nil {
		log.Fatalf("Error sending matrix: %v", err)
	}
	if err := bw.Flush(); err != nil {
		log.Fatalf("Failed to flush matrix buffer: %v", err)
	}
	if err := comm.node.send(context.Background(), dst, buf.Bytes()); err != nil {
		log.Fatalf("Failed to send matrix to %d: %v", dst, err)
	}
}

// RecvMatrix reads a lattice matrix of the given outer length from src.
func (comm *P2PComm) RecvMatrix(reader *bufio.Reader, src int, length int) structs.Matrix[ring.Poly] {
	if reader != nil && comm.hasLegacySock(src) {
		matrix := make(structs.Matrix[ring.Poly], length)
		if _, err := matrix.ReadFrom(reader); err != nil {
			log.Fatalf("Failed to read matrix: %v", err)
		}
		return matrix
	}
	body, err := comm.node.recvBody(src)
	if err != nil {
		log.Fatalf("Failed to recv matrix from %d: %v", src, err)
	}
	matrix := make(structs.Matrix[ring.Poly], length)
	if _, err := matrix.ReadFrom(bufio.NewReader(bytes.NewReader(body))); err != nil {
		log.Fatalf("Failed to read matrix: %v", err)
	}
	return matrix
}

// SendBytesSlice ships a slice of byte-slices to dst with explicit
// length tags. Wire layout: uint32 numSlices, then for each slice
// uint32 length + slice bytes.
func (comm *P2PComm) SendBytesSlice(writer *bufio.Writer, dst int, data [][]byte) {
	body := encodeBytesSlice(data)
	if writer != nil && comm.hasLegacySock(dst) {
		if _, err := writer.Write(body); err != nil {
			log.Fatalf("Failed to write bytes slice: %v", err)
		}
		if err := writer.Flush(); err != nil {
			log.Fatalf("Failed to flush writer: %v", err)
		}
		return
	}
	if err := comm.node.send(context.Background(), dst, body); err != nil {
		log.Fatalf("Failed to send bytes slice to %d: %v", dst, err)
	}
}

// RecvBytesSlice reads a length-prefixed slice-of-slices from src.
func (comm *P2PComm) RecvBytesSlice(reader *bufio.Reader, src int) [][]byte {
	if reader != nil && comm.hasLegacySock(src) {
		return decodeBytesSlice(reader)
	}
	body, err := comm.node.recvBody(src)
	if err != nil {
		log.Fatalf("Failed to recv bytes slice from %d: %v", src, err)
	}
	return decodeBytesSlice(bufio.NewReader(bytes.NewReader(body)))
}

// SendBytesMap ships a map<int,[]byte> to dst.
func (comm *P2PComm) SendBytesMap(writer *bufio.Writer, dst int, data map[int][]byte) {
	body := encodeBytesMap(data)
	if writer != nil && comm.hasLegacySock(dst) {
		if _, err := writer.Write(body); err != nil {
			log.Fatalf("Failed to write bytes map: %v", err)
		}
		if err := writer.Flush(); err != nil {
			log.Fatalf("Failed to flush writer: %v", err)
		}
		return
	}
	if err := comm.node.send(context.Background(), dst, body); err != nil {
		log.Fatalf("Failed to send bytes map to %d: %v", dst, err)
	}
}

// RecvBytesMap reads a map<int,[]byte> from src.
func (comm *P2PComm) RecvBytesMap(reader *bufio.Reader, src int) map[int][]byte {
	if reader != nil && comm.hasLegacySock(src) {
		return decodeBytesMap(reader)
	}
	body, err := comm.node.recvBody(src)
	if err != nil {
		log.Fatalf("Failed to recv bytes map from %d: %v", src, err)
	}
	return decodeBytesMap(bufio.NewReader(bytes.NewReader(body)))
}

// SendBytesSliceMap ships a map<int,[][]byte> to dst.
func (comm *P2PComm) SendBytesSliceMap(writer *bufio.Writer, dst int, data map[int][][]byte) {
	body := encodeBytesSliceMap(data)
	if writer != nil && comm.hasLegacySock(dst) {
		if _, err := writer.Write(body); err != nil {
			log.Fatalf("Failed to write bytes-slice map: %v", err)
		}
		if err := writer.Flush(); err != nil {
			log.Fatalf("Failed to flush writer: %v", err)
		}
		return
	}
	if err := comm.node.send(context.Background(), dst, body); err != nil {
		log.Fatalf("Failed to send bytes-slice map to %d: %v", dst, err)
	}
}

// RecvBytesSliceMap reads a map<int,[][]byte> from src.
func (comm *P2PComm) RecvBytesSliceMap(reader *bufio.Reader, src int) map[int][][]byte {
	if reader != nil && comm.hasLegacySock(src) {
		return decodeBytesSliceMap(reader)
	}
	body, err := comm.node.recvBody(src)
	if err != nil {
		log.Fatalf("Failed to recv bytes-slice map from %d: %v", src, err)
	}
	return decodeBytesSliceMap(bufio.NewReader(bytes.NewReader(body)))
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
