// Package wallet implements the core MPC wallet logic, including distributed
// key generation and signing using threshold ECDSA via the tss-lib library.
package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"

	"github.com/example/mpc-wallet/internal/network"
)

const (
	testPartyNumber = 3               // number of parties in this threshold scheme
	mtTSS           = "tss"           // message type for TSS protocol messages
	mtSignReq       = "sign_req"      // message type for signing requests
	msgTimeout      = 5 * time.Minute // timeout for each protocol round
)

// deterministicPartyIDs generates deterministic PartyID objects for n parties.
// Each PartyID is constructed with an index (1..n) so that all nodes share
// the same ordering.
func deterministicPartyIDs(n int) []*tss.PartyID {
	out := make([]*tss.PartyID, n)
	for i := 0; i < n; i++ {
		idStr := strconv.Itoa(i + 1)
		out[i] = tss.NewPartyID(idStr, fmt.Sprintf("P[%d]", i+1), big.NewInt(int64(i+1)))
	}
	tss.SortPartyIDs(out)
	return out
}

// Config holds parameters needed to initialize a Wallet.
type Config struct {
	NodeID  int             // this node's index (1-based)
	DataDir string          // directory to store key shares
	Router  *network.Router // network router for message passing
}

// Wallet represents a local MPC wallet instance, including state for key shares,
// the current running TSS protocol, and the collective public key.
type Wallet struct {
	cfg      Config
	privData *keygen.LocalPartySaveData // saved TSS key-generation state
	pubKey   *ecdsa.PublicKey           // collective ECDSA public key

	mu    sync.RWMutex   // guards party and pIDs
	party tss.Party      // current TSS party instance (keygen or signing)
	pIDs  []*tss.PartyID // list of all party IDs for protocol rounds
}

// NewWallet creates a new Wallet backed by the given Config. If a previously
// generated key share exists on disk, it is loaded. Then a background goroutine
// is started to handle incoming messages from the network.
func NewWallet(c Config) (*Wallet, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return nil, err
	}

	w := &Wallet{cfg: c}
	// Attempt to load an existing local key share from disk
	if err := w.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Start background goroutine to handle incoming TSS and sign_req messages
	go w.messageHandler()
	return w, nil
}

// keystorePath returns the path to the JSON file where this node's key share is saved.
func (w *Wallet) keystorePath() string {
	return filepath.Join(w.cfg.DataDir, fmt.Sprintf("party_%d_save.json", w.cfg.NodeID))
}

// load tries to read and unmarshal the local party's key-generation save data.
// If successful, privData and pubKey are set, indicating HasKey() will return true.
func (w *Wallet) load() error {
	b, err := os.ReadFile(w.keystorePath())
	if err != nil {
		return err
	}
	save := new(keygen.LocalPartySaveData)
	if err := json.Unmarshal(b, save); err != nil {
		return err
	}
	// Construct the ECDSA public key from saved data
	w.privData = save
	w.pubKey = &ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     save.ECDSAPub.X(),
		Y:     save.ECDSAPub.Y(),
	}
	fmt.Printf("[%s] Node %d: Loaded existing key share.\n",
		time.Now().Format("15:04:05"), w.cfg.NodeID)
	return nil
}

// persist saves the current LocalPartySaveData (key share) to disk as JSON.
func (w *Wallet) persist() error {
	if w.privData == nil {
		return errors.New("no key data")
	}
	if err := os.MkdirAll(w.cfg.DataDir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(w.privData)
	if err := os.WriteFile(w.keystorePath(), b, 0o600); err != nil {
		return err
	}
	fmt.Printf("[%s] Node %d: Persisted key share.\n",
		time.Now().Format("15:04:05"), w.cfg.NodeID)
	return nil
}

// HasKey returns true if a local key share has been loaded or generated.
func (w *Wallet) HasKey() bool { return w.privData != nil }

// PubKeyHex returns the collective ECDSA public key as a hex-encoded string.
// Returns empty string if no public key is available.
func (w *Wallet) PubKeyHex() string {
	if w.pubKey == nil {
		return ""
	}
	return hex.EncodeToString(append(w.pubKey.X.Bytes(), w.pubKey.Y.Bytes()...))
}

// messageHandler listens on the Router's inbound channel for Envelope messages.
// Based on Envelope.Type, it dispatches to handleTSS or handleSignRequest.
func (w *Wallet) messageHandler() {
	for env := range w.cfg.Router.Recv() {
		switch env.Type {
		case mtTSS:
			w.handleTSS(env)
		case mtSignReq:
			w.handleSignRequest(env.Data)
		}
	}
}

// RunKeygen executes the distributed key-generation protocol across all peers.
// It waits for network readiness, sets up a new TSS keygen party, and persists
// the resulting key share when complete.
func (w *Wallet) RunKeygen(ctx context.Context) error {
	// Wait until connections to all other peers are established
	if err := w.cfg.Router.WaitUntilReady(5 * time.Second); err != nil {
		return err
	}

	// Create deterministic party IDs for all participants
	pIDs := deterministicPartyIDs(testPartyNumber)
	params := tss.NewParameters(
		tss.S256(),
		tss.NewPeerContext(pIDs),
		pIDs[w.cfg.NodeID-1],
		testPartyNumber,
		testPartyNumber-1,
	)

	outCh := make(chan tss.Message, 100)
	endCh := make(chan *keygen.LocalPartySaveData, 1)

	// Lock and set up the local TSS party for key generation
	w.mu.Lock()
	w.party, w.pIDs = keygen.NewLocalParty(params, outCh, endCh), pIDs
	w.mu.Unlock()

	// Start the keygen protocol in a new goroutine
	go func() { _ = w.party.Start() }()
	fmt.Printf("[%s] Node %d: Key-gen party started.\n",
		time.Now().Format("15:04:05"), w.cfg.NodeID)

	// Process outgoing TSS messages and wait for completion or timeout
	for {
		select {
		case m := <-outCh:
			// For each TSS message, serialize and send via router
			if err := w.sendTSS(m); err != nil {
				return err
			}
		case save := <-endCh:
			// Key-gen finished: save local data and set public key
			w.privData = save
			w.pubKey = &ecdsa.PublicKey{
				Curve: tss.S256(),
				X:     save.ECDSAPub.X(),
				Y:     save.ECDSAPub.Y(),
			}
			w.mu.Lock()
			w.party = nil
			w.mu.Unlock()
			fmt.Printf("[%s] Node %d: Key-gen complete, pubkey: %s\n",
				time.Now().Format("15:04:05"), w.cfg.NodeID, w.PubKeyHex())
			return w.persist()
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(msgTimeout):
			return errors.New("key-gen timeout")
		}
	}
}

// Sign initiates a distributed signing round for the given message bytes.
// It ensures the key share exists, waits for network readiness, broadcasts
// a signing request, and then delegates to startSigningRound.
func (w *Wallet) Sign(ctx context.Context, msg []byte) (*common.SignatureData, error) {
	if !w.HasKey() {
		return nil, errors.New("no key share – run key-gen first")
	}
	if err := w.cfg.Router.WaitUntilReady(5 * time.Second); err != nil {
		return nil, err
	}

	// Broadcast the signing request to all peers (To == 0 for broadcast)
	if err := w.cfg.Router.Send(0, mtSignReq, msg); err != nil {
		return nil, err
	}
	return w.startSigningRound(ctx, msg)
}

// startSigningRound sets up and runs a new TSS signing party using the given message.
// This is invoked either after a local Sign() call or in response to a sign_req from a peer.
func (w *Wallet) startSigningRound(ctx context.Context, msg []byte) (*common.SignatureData, error) {
	// Create deterministic party IDs for signing
	pIDs := deterministicPartyIDs(testPartyNumber)
	params := tss.NewParameters(
		tss.S256(),
		tss.NewPeerContext(pIDs),
		pIDs[w.cfg.NodeID-1],
		testPartyNumber,
		testPartyNumber-1,
	)

	outCh := make(chan tss.Message, 100)
	endCh := make(chan *common.SignatureData, 1)

	// Compute message digest
	h := sha256.Sum256(msg)

	// Prevent concurrent protocol rounds on the same node
	w.mu.Lock()
	if w.party != nil {
		w.mu.Unlock()
		return nil, errors.New("another protocol round in progress")
	}
	// Initialize a new signing party with the local key share
	w.party, w.pIDs = signing.NewLocalParty(new(big.Int).SetBytes(h[:]), params, *w.privData, outCh, endCh), pIDs
	w.mu.Unlock()

	// Launch the signing protocol
	go func() { _ = w.party.Start() }()
	fmt.Printf("[%s] Node %d: Signing party started.\n",
		time.Now().Format("15:04:05"), w.cfg.NodeID)

	// Process outgoing TSS messages and wait for signature or timeout
	for {
		select {
		case m := <-outCh:
			if err := w.sendTSS(m); err != nil {
				return nil, err
			}
		case sig := <-endCh:
			// Signing complete: clear party and return signature
			w.mu.Lock()
			w.party = nil
			w.mu.Unlock()
			return sig, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(msgTimeout):
			return nil, errors.New("signing timeout")
		}
	}
}

// handleSignRequest processes an incoming sign_req message by spawning a new signing
// round in its own goroutine. This ensures the request is handled asynchronously.
func (w *Wallet) handleSignRequest(msg []byte) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), msgTimeout)
		defer cancel()

		if _, err := w.startSigningRound(ctx, msg); err != nil {
			fmt.Printf("[%s] Node %d: sign error: %v\n",
				time.Now().Format("15:04:05"), w.cfg.NodeID, err)
		}
	}()
}

// sendTSS serializes a TSS message (m) and sends it via the Router as an Envelope.
// It inspects m.GetTo() to determine the recipient: either broadcast (To == 0) or specific peer.
func (w *Wallet) sendTSS(m tss.Message) error {
	b, _, err := m.WireBytes()
	if err != nil {
		return err
	}
	to := 0
	if dst := m.GetTo(); len(dst) == 1 {
		to = dst[0].Index + 1
	}
	return w.cfg.Router.Send(to, mtTSS, b)
}

// handleTSS takes an incoming Envelope of type "tss" and delivers its payload to the active
// TSS party. It looks up the sender's PartyID using w.pIDs and passes isBroadcast=false if
// env.To != 0, or true if env.To==0.
func (w *Wallet) handleTSS(env network.Envelope) {
	w.mu.RLock()
	party, ids := w.party, w.pIDs
	w.mu.RUnlock()

	// If no protocol is in progress or invalid sender, ignore
	if party == nil || len(ids) == 0 || env.From < 1 || env.From > len(ids) {
		return
	}
	fromPID := ids[env.From-1]
	isBroadcast := env.To == 0

	// Pass the raw bytes into the TSS party
	if _, err := party.UpdateFromBytes(env.Data, fromPID, isBroadcast); err != nil {
		fmt.Printf("[%s] Node %d: inbound TSS error: %v\n",
			time.Now().Format("15:04:05"), w.cfg.NodeID, err)
	}
}
