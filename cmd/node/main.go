package main

import (
	"bufio"
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/viper"

	"github.com/example/mpc-wallet/internal/network"
	"github.com/example/mpc-wallet/internal/wallet"
)

const (
	keyNodeID  = "node_id"
	keyPeers   = "peers"
	keyDataDir = "data_dir"
)

// main is the entry point for the MPC wallet node application. It parses command-line flags,
// loads configuration, establishes network connections, and enters a loop to accept messages
// from stdin to be signed.
func main() {
	// Parse command-line flags
	cfgPath := flag.String("config", "", "Path to YAML config (required)")
	cliID := flag.Int("node_id", 0, "Override node_id from YAML (optional)")
	flag.Parse()
	if *cfgPath == "" {
		log.Fatalln("--config is required")
	}

	// Load YAML configuration using Viper
	v := viper.New()
	v.SetConfigFile(*cfgPath)
	if err := v.ReadInConfig(); err != nil {
		log.Fatalf("read config: %v", err)
	}

	// If the node_id is overridden by a CLI flag, update Viper
	if *cliID != 0 {
		v.Set(keyNodeID, *cliID)
	}
	selfID := v.GetInt(keyNodeID)
	if selfID == 0 {
		log.Fatalln("node_id missing (YAML or --node_id)")
	}

	// Parse peers map from configuration: map[string]string → map[int]string
	raw := v.GetStringMapString(keyPeers)
	if len(raw) == 0 {
		log.Fatalln("peers map is empty in YAML")
	}
	peers := make(map[int]string, len(raw))
	for k, addr := range raw {
		id, err := strconv.Atoi(k)
		if err != nil {
			log.Fatalf("invalid peer id %q: %v", k, err)
		}
		peers[id] = addr
	}

	// Determine this node's own address from the peers map
	selfAddr, ok := peers[selfID]
	if !ok {
		log.Fatalf("own node_id %d not present in peers map", selfID)
	}
	// Extract port from the host:port string
	_, portStr, err := net.SplitHostPort(selfAddr)
	if err != nil {
		log.Fatalf("cannot parse address %q for self: %v", selfAddr, err)
	}
	listenPort, _ := strconv.Atoi(portStr)

	// Retrieve data directory from config
	dataDir := strings.TrimSpace(v.GetString(keyDataDir))
	if dataDir == "" {
		log.Fatalln("data_dir missing in YAML")
	}

	// Initialize the network router for sending/receiving Envelope messages
	router := network.NewRouter(selfID, listenPort, peers)
	if err := router.Start(); err != nil {
		log.Fatalf("router start: %v", err)
	}

	// Initialize the MPC wallet, possibly loading an existing key share
	w, err := wallet.NewWallet(wallet.Config{
		NodeID:  selfID,
		DataDir: dataDir,
		Router:  router,
	})
	if err != nil {
		log.Fatalf("wallet init: %v", err)
	}

	// If no local key share exists yet, run distributed key generation
	if !w.HasKey() {
		log.Println("no local key share – running distributed key-gen…")
		if err := w.RunKeygen(context.Background()); err != nil {
			log.Fatalf("key-gen failed: %v", err)
		}
		log.Println("key-gen complete, public key:", w.PubKeyHex())
	}

	// Set up channel to handle termination signals (SIGINT, SIGTERM)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Prepare to read lines from stdin for signing requests
	reader := bufio.NewReader(os.Stdin)
	log.Println("ready – type a message and press ↵ to sign, or Ctrl-C to exit")

	for {
		// Spawn a goroutine to read from stdin (so we can also listen for signals)
		inputCh := make(chan string, 1)
		errCh := make(chan error, 1)
		go func() {
			text, err := reader.ReadString('\n')
			if err != nil {
				errCh <- err
			} else {
				inputCh <- text
			}
		}()

		select {
		case <-sigCh:
			// On shutdown signal, close router and exit
			log.Println("shutting down…")
			router.Close()
			return

		case text := <-inputCh:
			// Received a line from stdin: trim whitespace and sign if non-empty
			msg := strings.TrimSpace(text)
			if msg == "" {
				continue
			}
			sig, err := w.Sign(context.Background(), []byte(msg))
			if err != nil {
				log.Printf("sign error: %v", err)
				continue
			}
			// Log signature values (r, s) in hex
			log.Printf("r=%#x\ns=%#x", sig.R, sig.S)

		case err := <-errCh:
			// Error reading from stdin; log and continue
			log.Printf("read error: %v", err)
			continue
		}
	}
}
