package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/example/mpc-wallet/internal/network"
)

// TestKeygenAndSimpleSign verifies that three nodes can collaboratively run
// distributed key generation and produce a valid threshold ECDSA signature.
// It spins up three Router instances and three Wallets, performs key-gen,
// ensures the public keys match, signs a test message, and verifies the signature.
func TestKeygenAndSimpleSign(t *testing.T) {
	const n = 3
	basePort := 18011

	// Build a map of peer IDs to their localhost addresses
	peers := make(map[int]string, n)
	for i := 1; i <= n; i++ {
		peers[i] = "127.0.0.1:" + strconv.Itoa(basePort+(i-1))
	}

	var routers [n]*network.Router
	var wallets [n]*Wallet

	// Use a temporary directory as the root for storing each node's data
	rootTmp := t.TempDir()
	for i := 0; i < n; i++ {
		nodeID := i + 1
		port := basePort + i

		// Initialize a Router for each node
		r := network.NewRouter(nodeID, port, peers)
		routers[i] = r

		// Create a data directory for Wallet's key share
		dataDir := filepath.Join(rootTmp, "node"+strconv.Itoa(nodeID))
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dataDir, err)
		}

		// Instantiate a Wallet for each node, which loads any existing key share
		w, err := NewWallet(Config{
			NodeID:  nodeID,
			DataDir: dataDir,
			Router:  r,
		})
		if err != nil {
			t.Fatalf("NewWallet(node %d) error: %v", nodeID, err)
		}
		wallets[i] = w
	}

	// Run distributed key generation concurrently across all nodes with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := wallets[i].RunKeygen(ctx); err != nil {
				t.Errorf("node %d: RunKeygen failed: %v", i+1, err)
			}
		}(i)
	}
	wg.Wait()

	// Verify that all nodes share the same public key
	pub0 := wallets[0].PubKeyHex()
	for i := 1; i < n; i++ {
		if wallets[i].PubKeyHex() != pub0 {
			t.Fatalf("public key mismatch: node1=%q, node%d=%q",
				pub0, i+1, wallets[i].PubKeyHex())
		}
	}
	t.Logf("All %d nodes share the same pubkey: %s", n, pub0)

	// Prepare a test message and have node 1 sign it
	message := []byte("hello")
	sig, err := wallets[0].Sign(ctx, message)
	if err != nil {
		t.Fatalf("node 1: Sign returned error: %v", err)
	}

	// Decode the shared public key from hex to an ECDSA public key object
	pkBytes, err := hex.DecodeString(pub0)
	if err != nil {
		t.Fatalf("hex.DecodeString(pub0) failed: %v", err)
	}
	half := len(pkBytes) / 2
	x := new(big.Int).SetBytes(pkBytes[:half])
	y := new(big.Int).SetBytes(pkBytes[half:])
	pubkey := &ecdsa.PublicKey{Curve: tss.S256(), X: x, Y: y}

	// Convert signature components from bytes to big.Int
	r := new(big.Int).SetBytes(sig.R)
	s := new(big.Int).SetBytes(sig.S)

	// Verify the signature on the hashed message
	hash := sha256.Sum256(message)
	if !ecdsa.Verify(pubkey, hash[:], r, s) {
		t.Fatal("ECDSA.Verify failed on the signature from node 1")
	}
	t.Log("Signature is valid under the collective public key.")

	// Close all routers to clean up
	for i := 0; i < n; i++ {
		routers[i].Close()
	}
}
