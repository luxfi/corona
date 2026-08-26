package main

import (
	"bufio"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/corona/networking"
	"github.com/luxfi/corona/primitives"
	"github.com/luxfi/corona/sign"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go partyID")
		os.Exit(1)
	}

	partyIDString := os.Args[1]

	iters, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("Error: Please enter a valid integer.")
		os.Exit(1)
	}

	parties, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Println("Error: Please enter a valid integer.")
		os.Exit(1)
	}
	sign.K = parties
	sign.Threshold = parties

	if partyIDString == "l" {
		if err := sign.LocalRun(iters); err != nil {
			log.Fatalf("local run: %v", err)
		}
		return
	}

	partyID, err := strconv.Atoi(partyIDString)
	if err != nil {
		fmt.Println("Error: Please enter a valid integer.")
		os.Exit(1)
	}

	// Initialize P2P communication over ZAP transport.
	//
	// Peers and their listen addresses come from the CORONA_PEERS env
	// var, formatted as "rank=host:port,rank=host:port,...". The local
	// party's own rank is excluded; every other rank in the ceremony
	// must be present. The local listen port is derived from the same
	// list (peerAddrs[partyID] specifies "host:port" we bind on).
	peerAddrs, listenPort, err := parsePeerEnv(os.Getenv("CORONA_PEERS"), partyID)
	if err != nil {
		log.Fatalf("CORONA_PEERS: %v", err)
	}
	comm, err := networking.NewP2PComm(partyID, listenPort, true /*noDiscovery*/, nil)
	if err != nil {
		log.Fatalf("NewP2PComm: %v", err)
	}
	defer comm.Close()
	// Suppress unused-import error from prior wiring.
	_ = (*net.Conn)(nil)

	if err := comm.EstablishConnectionsZAP(partyID, sign.K, peerAddrs); err != nil {
		log.Fatalf("EstablishConnectionsZAP: %v", err)
	}

	var setupDuration, genDuration, signRound1Duration, signRound2PreprocessDuration, signRound2Duration, finalizeDuration, verifyDuration time.Duration
	var genStart, genEnd, signRound1Start, signRound1End, signRound2Start, signRound2End, combinerReceiveEnd, combinerFinalizeEnd time.Time
	var A structs.Matrix[ring.Poly]
	var b structs.Vector[ring.Poly]
	randomKey := make([]byte, sign.KeySize)
	r, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	r_xi, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QXi})
	r_nu, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QNu})
	prng, _ := sampling.NewKeyedPRNG(randomKey)
	uniformSampler := ring.NewUniformSampler(prng, r)
	trustedDealerKey := randomKey
	// Create your own party
	party := sign.NewParty(partyID, r, r_xi, r_nu, uniformSampler)

	// Variables to be used in SIGNATURE ROUNDS
	D := make(map[int]structs.Matrix[ring.Poly])
	MACs := make(map[int]map[int][]byte)
	mu := "Message"
	T := make([]int, sign.K)
	for i := 0; i < sign.K; i++ {
		T[i] = i
	}
	lagrangeCoeffs := primitives.ComputeLagrangeCoefficients(r, T, big.NewInt(int64(sign.Q)))

	// Trusted dealer
	if partyID == sign.TrustedDealerID {
		// GEN: Generate secret shares, seeds, and MAC keys
		start := time.Now()
		AMat, skShares, seeds, MACKeys, bVec := sign.Gen(r, r_xi, uniformSampler, trustedDealerKey, lagrangeCoeffs)

		b = bVec
		A = AMat
		genDuration = time.Since(start)
		genStart = time.Now()

		// Give party 0 its own values
		party.SkShare = skShares[partyID]
		party.Seed = seeds
		party.MACKeys = MACKeys[partyID]

		// Send out public information & trusted dealer data
		var sendWg sync.WaitGroup
		for i := 0; i < sign.K; i++ {
			if i != sign.TrustedDealerID {
				sendWg.Add(1)
				go func(i int) {
					defer sendWg.Done()
					writer := bufio.NewWriter(*comm.GetSock(i))
					if err := comm.SendVector(writer, i, b); err != nil {
						log.Fatalf("send to peer: %v", err)
					}
					if err := comm.SendMatrix(writer, i, A); err != nil {
						log.Fatalf("send to peer: %v", err)
					}
					if err := comm.SendVector(writer, i, skShares[i]); err != nil {
						log.Fatalf("send to peer: %v", err)
					}
					if err := comm.SendBytesSliceMap(writer, i, seeds); err != nil {
						log.Fatalf("send to peer: %v", err)
					}
					if err := comm.SendBytesMap(writer, i, MACKeys[i]); err != nil {
						log.Fatalf("send to peer: %v", err)
					}
				}(i)
			}
		}
		sendWg.Wait()
		genEnd = time.Now()
	} else {
		reader := bufio.NewReader(*comm.GetSock(sign.TrustedDealerID))
		b, err = comm.RecvVector(reader, sign.TrustedDealerID, sign.M)
		if err != nil {
			log.Fatalf("recv vector from peer: %v", err)
		}
		A, err = comm.RecvMatrix(reader, sign.TrustedDealerID, sign.M)
		if err != nil {
			log.Fatalf("recv matrix from peer: %v", err)
		}
		party.SkShare, err = comm.RecvVector(reader, sign.TrustedDealerID, sign.N)
		if err != nil {
			log.Fatalf("recv vector from peer: %v", err)
		}
		party.Seed, err = comm.RecvBytesSliceMap(reader, sign.TrustedDealerID)
		if err != nil {
			log.Fatalf("recv seed map from peer: %v", err)
		}
		party.MACKeys, err = comm.RecvBytesMap(reader, sign.TrustedDealerID)
		if err != nil {
			log.Fatalf("recv MAC keys from peer: %v", err)
		}
	}

	time.Sleep(time.Second * 5)
	// SIGNATURE ROUND 1
	sid := 1
	PRFKey := "PRFKey"

	r.NTT(lagrangeCoeffs[partyID], lagrangeCoeffs[partyID])
	r.MForm(lagrangeCoeffs[partyID], lagrangeCoeffs[partyID])
	party.Lambda = lagrangeCoeffs[partyID]

	fmt.Printf("Timestamp before Sign Round 1 compute: %s\n", time.Now().Format("15:04:05.000000"))
	start := time.Now()
	var r1err error
	D[partyID], MACs[partyID], r1err = party.SignRound1(A, sid, []byte(PRFKey), T)
	if r1err != nil {
		log.Fatalf("SignRound1 failed for party %d: %v", partyID, r1err)
	}
	signRound1Duration = time.Since(start)
	log.Println("Completed R1")

	signRound1Start = time.Now()
	// Concurrently send and receive data
	var round1Wg sync.WaitGroup
	for i := 0; i < sign.K; i++ {
		if i != partyID {
			round1Wg.Add(2)
			go func(i int) {
				defer round1Wg.Done()
				writer := bufio.NewWriter(*comm.GetSock(i))
				if err := comm.SendMatrix(writer, i, D[partyID]); err != nil {
					log.Fatalf("send to peer: %v", err)
				}
				if err := comm.SendBytesMap(writer, i, MACs[partyID]); err != nil {
					log.Fatalf("send to peer: %v", err)
				}
			}(i)

			go func(i int) {
				defer round1Wg.Done()
				reader := bufio.NewReader(*comm.GetSock(i))
				D[i], err = comm.RecvMatrix(reader, i, sign.M)
				if err != nil {
					log.Fatalf("recv matrix from peer: %v", err)
				}
				MACs[i], err = comm.RecvBytesMap(reader, i)
				if err != nil {
					log.Fatalf("recv MAC keys from peer: %v", err)
				}
			}(i)
		}
	}
	round1Wg.Wait()
	signRound1End = time.Now()

	// SIGN ROUND 2
	z := make(map[int]structs.Vector[ring.Poly])

	fmt.Printf("Timestamp before Sign Round 1 verify: %s\n", time.Now().Format("15:04:05.000000"))
	start = time.Now()
	valid, DSum, hash := party.SignRound2Preprocess(A, b, D, MACs, sid, T)
	if !valid {
		log.Fatalf("MAC verification failed for party %d", partyID)
	} else {
		log.Println("Verification passed, moving onto round 2")
	}
	signRound2PreprocessDuration = time.Since(start)

	fmt.Printf("Timestamp before Sign Round 2 compute: %s\n", time.Now().Format("15:04:05.000000"))
	start = time.Now()
	z[partyID] = party.SignRound2(A, b, DSum, sid, mu, T, []byte(PRFKey), hash)
	signRound2Duration = time.Since(start)

	signRound2Start = time.Now()
	if partyID != sign.CombinerID {
		writer := bufio.NewWriter(*comm.GetSock(sign.CombinerID))
		if err := comm.SendVector(writer, sign.CombinerID, z[partyID]); err != nil {
			log.Fatalf("send to peer: %v", err)
		}
		signRound2End = time.Now()
	} else {
		for i := 0; i < sign.K; i++ {
			if i != sign.CombinerID {
				reader := bufio.NewReader(*comm.GetSock(i))
				z[i], err = comm.RecvVector(reader, i, sign.N)
				if err != nil {
					log.Fatalf("recv vector from peer: %v", err)
				}
			}
		}
		combinerReceiveEnd = time.Now()

		fmt.Printf("Timestamp before Finalize: %s\n", time.Now().Format("15:04:05.000000"))
		// SIGNATURE FINALIZE
		start := time.Now()
		_, sig, Delta := party.SignFinalize(z, A, b)
		finalizeDuration = time.Since(start)
		combinerFinalizeEnd = time.Now()
		// Verify the signature
		start = time.Now()
		verified := sign.Verify(r, r_xi, r_nu, sig, A, mu, b, party.C, Delta)
		verifyDuration = time.Since(start)
		fmt.Printf("Signature Verification Result: %v\n", verified)
	}

	// Print all durations
	fmt.Println("Setup duration:", setupDuration)
	fmt.Println("Gen duration:", genDuration)
	fmt.Println("Signature Round 1 duration:", signRound1Duration)
	fmt.Println("Signature Round 1 verify duration:", signRound2PreprocessDuration)
	fmt.Println("Signature Round 2 duration:", signRound2Duration)
	fmt.Println("Finalize duration:", finalizeDuration)
	fmt.Println("Verify duration:", verifyDuration)

	// Print timestamps for networking
	fmt.Printf("Gen start timestamp: %s\n", genStart.Format("15:04:05.000000"))
	fmt.Printf("Gen end timestamp: %s\n", genEnd.Format("15:04:05.000000"))

	fmt.Printf("Sign Round 1 sending/receiving start timestamp: %s\n", signRound1Start.Format("15:04:05.000000"))
	fmt.Printf("Sign Round 1 sending/receiving end timestamp: %s\n", signRound1End.Format("15:04:05.000000"))

	fmt.Printf("Sign Round 2 sending/receiving start timestamp: %s\n", signRound2Start.Format("15:04:05.000000"))
	fmt.Printf("Sign Round 2 sending end timestamp: %s\n", signRound2End.Format("15:04:05.000000"))

	if partyID == sign.CombinerID {
		fmt.Printf("Combiner receive end timestamp: %s\n", combinerReceiveEnd.Format("15:04:05.000000"))
		fmt.Printf("Combiner finalize end timestamp: %s\n", combinerFinalizeEnd.Format("15:04:05.000000"))
	}
}

// parsePeerEnv parses the CORONA_PEERS env var into a per-rank address
// map, and returns the local listen port for partyID.
//
// Format: "0=host:port,1=host:port,...". Every rank in the ceremony
// must appear. The local party's entry is dropped from the returned
// map but its port is harvested as the listen port.
//
// Returns an error on malformed input or when partyID is absent.
func parsePeerEnv(raw string, partyID int) (map[int]string, int, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, 0, fmt.Errorf("CORONA_PEERS is empty (format: rank=host:port,rank=host:port,...)")
	}
	peerAddrs := make(map[int]string)
	listenPort := 0
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		eq := strings.IndexByte(entry, '=')
		if eq < 0 {
			return nil, 0, fmt.Errorf("CORONA_PEERS entry %q missing '='", entry)
		}
		rank, err := strconv.Atoi(strings.TrimSpace(entry[:eq]))
		if err != nil {
			return nil, 0, fmt.Errorf("CORONA_PEERS entry %q: %w", entry, err)
		}
		addr := strings.TrimSpace(entry[eq+1:])
		if addr == "" {
			return nil, 0, fmt.Errorf("CORONA_PEERS entry %q has empty address", entry)
		}
		if rank == partyID {
			// Local listen port from "host:port" — the host is ignored
			// (we always listen on all interfaces).
			_, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, 0, fmt.Errorf("CORONA_PEERS local addr %q: %w", addr, err)
			}
			p, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, 0, fmt.Errorf("CORONA_PEERS local port %q: %w", portStr, err)
			}
			listenPort = p
			continue
		}
		peerAddrs[rank] = addr
	}
	if listenPort == 0 {
		return nil, 0, fmt.Errorf("CORONA_PEERS missing entry for local rank %d", partyID)
	}
	return peerAddrs, listenPort, nil
}
