// Package network provides a Router for sending and receiving Envelope messages
// between MPC nodes in a peer-to-peer fashion.
package network

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Envelope represents a network message sent between nodes.
// From: sender node ID, To: recipient node ID (0 means broadcast to all peers),
// Type: message type (e.g., "tss"), Data: raw payload.
type Envelope struct {
	From int    `json:"from"`
	To   int    `json:"to"`
	Type string `json:"type"`
	Data []byte `json:"data"`
}

// Router manages TCP connections to peers and provides send/receive channels
// for Envelope messages. It handles dialing, accepting, and multiplexing I/O.
type Router struct {
	nodeID   int
	port     int
	peers    map[int]string        // map of peer ID → address
	outCh    chan Envelope         // outbound messages to send
	inCh     chan Envelope         // inbound messages received
	conns    map[int]net.Conn      // active connections keyed by peer ID
	connMu   sync.RWMutex          // guards conns map
	allConns map[net.Conn]struct{} // all connections for cleanup
	allMu    sync.Mutex            // guards allConns
	stopCh   chan struct{}         // signals router shutdown
	wg       sync.WaitGroup        // waits for goroutines to finish
	listener net.Listener          // TCP listener for incoming connections
}

// NewRouter creates a new Router for the given nodeID, listening on the given port,
// and with a map of peer IDs to addresses. It starts the internal goroutine to
// accept/dial/manage connections.
func NewRouter(nodeID, port int, peers map[int]string) *Router {
	r := &Router{
		nodeID:   nodeID,
		port:     port,
		peers:    peers,
		outCh:    make(chan Envelope, 100),
		inCh:     make(chan Envelope, 100),
		conns:    make(map[int]net.Conn),
		allConns: make(map[net.Conn]struct{}),
		stopCh:   make(chan struct{}),
	}
	// Start listening, dialing, and outbound loops in background
	go r.start()
	return r
}

// Start logs initialization of the router. Actual network loops have already begun
// in NewRouter via r.start().
func (r *Router) Start() error {
	fmt.Printf("[%s] Node %d: Router initialized and background processes running.\n",
		time.Now().Format("15:04:05"), r.nodeID)
	return nil
}

// Send enqueues an Envelope for transmission. If To == 0, it's broadcast to all peers;
// otherwise, it sends only to the specified peer. Returns an error if the router is shutting down.
func (r *Router) Send(to int, msgType string, data []byte) error {
	select {
	case r.outCh <- Envelope{From: r.nodeID, To: to, Type: msgType, Data: data}:
		return nil
	case <-r.stopCh:
		return fmt.Errorf("router is stopping")
	}
}

// Recv returns a receive-only channel from which inbound Envelope messages can be read.
func (r *Router) Recv() <-chan Envelope {
	return r.inCh
}

// Close shuts down the router: stops listener, closes all connections, and waits for
// all background goroutines to finish.
func (r *Router) Close() {
	fmt.Printf("[%s] Node %d: Router stopping…\n", time.Now().Format("15:04:05"), r.nodeID)
	close(r.stopCh)

	// Close the listener so acceptLoop will exit
	if r.listener != nil {
		_ = r.listener.Close()
	}

	// Close all active connections
	r.allMu.Lock()
	for conn := range r.allConns {
		_ = conn.Close()
	}
	r.allMu.Unlock()

	// Wait for all internal goroutines to finish
	r.wg.Wait()

	fmt.Printf("[%s] Node %d: Router stopped.\n", time.Now().Format("15:04:05"), r.nodeID)
}

// WaitUntilReady blocks until this node has established TCP connections to all other peers
// or until the timeout expires. Returns an error if the router is stopping or if timeout.
func (r *Router) WaitUntilReady(timeout time.Duration) error {
	want := len(r.peers) - 1 // number of connections expected (excluding self)
	deadline := time.Now().Add(timeout)

	for {
		// Check how many peers we are connected to
		r.connMu.RLock()
		n := len(r.conns)
		r.connMu.RUnlock()
		if n >= want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("router: waited %.0fs but only %d/%d connections established",
				timeout.Seconds(), n, want)
		}
		select {
		case <-r.stopCh:
			return fmt.Errorf("router stopping")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// start launches the listener, the accept loop, the dial loop, and the outbound loop.
func (r *Router) start() {
	r.wg.Add(1)
	defer r.wg.Done()

	// Begin listening for incoming TCP connections on the configured port
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", r.port))
	if err != nil {
		fmt.Printf("[%s] Node %d: listen error: %v\n",
			time.Now().Format("15:04:05"), r.nodeID, err)
		return
	}
	r.listener = l

	fmt.Printf("[%s] Node %d: Listening on %d.\n",
		time.Now().Format("15:04:05"), r.nodeID, r.port)
	// Start acceptLoop to handle incoming connections
	go r.acceptLoop(l)
	// Start dialLoop to establish outgoing connections
	go r.dialLoop()
	// Start outboundLoop to dispatch messages from outCh to peers
	go r.outboundLoop()
}

// acceptLoop continuously accepts new inbound connections and dispatches each to handleConn.
func (r *Router) acceptLoop(l net.Listener) {
	r.wg.Add(1)
	defer r.wg.Done()
	// Explicitly ignore error return from l.Close() on exit
	defer func() {
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-r.stopCh:
				return
			default:
				fmt.Printf("[%s] Node %d: accept error: %v\n",
					time.Now().Format("15:04:05"), r.nodeID, err)
				continue
			}
		}

		// Track this connection for later cleanup
		r.allMu.Lock()
		r.allConns[conn] = struct{}{}
		r.allMu.Unlock()

		// Handle all reads from this connection
		go r.handleConn(conn)
	}
}

// dialLoop iterates over the peer list (excluding self) and spawns dialOne for each.
func (r *Router) dialLoop() {
	r.wg.Add(1)
	defer r.wg.Done()

	for peerID, addr := range r.peers {
		if peerID == r.nodeID {
			continue
		}
		go r.dialOne(peerID, addr)
	}
}

// dialOne attempts to establish a TCP connection to a single peer repeatedly until success or shutdown.
func (r *Router) dialOne(peerID int, addr string) {
	for {
		select {
		case <-r.stopCh:
			return
		default:
			fmt.Printf("[%s] Node %d: Dialing %d at %s…\n",
				time.Now().Format("15:04:05"), r.nodeID, peerID, addr)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				// Retry after a delay if dialing fails
				time.Sleep(time.Second)
				continue
			}

			// Track this connection
			r.allMu.Lock()
			r.allConns[conn] = struct{}{}
			r.allMu.Unlock()

			// Add to the map of active connections
			r.connMu.Lock()
			r.conns[peerID] = conn
			r.connMu.Unlock()

			fmt.Printf("[%s] Node %d: Connected to %d.\n",
				time.Now().Format("15:04:05"), r.nodeID, peerID)
			// Once connected, handle incoming messages on this connection
			r.handleConn(conn)
			return
		}
	}
}

// outboundLoop reads from outCh and writes each Envelope to the appropriate peer(s).
func (r *Router) outboundLoop() {
	r.wg.Add(1)
	defer r.wg.Done()

	for {
		select {
		case <-r.stopCh:
			return

		case env := <-r.outCh:
			if env.To == 0 {
				// Broadcast to all peers except self
				r.connMu.RLock()
				for id, c := range r.conns {
					if id != r.nodeID {
						r.writeMsg(c, env)
					}
				}
				r.connMu.RUnlock()
			} else {
				// Send to a single peer
				r.connMu.RLock()
				c := r.conns[env.To]
				r.connMu.RUnlock()
				if c != nil {
					r.writeMsg(c, env)
				}
			}
		}
	}
}

// writeMsg serializes the Envelope (header + type + data) and writes it to the TCP connection.
// The header is structured as:
//
//	[0:4]   little-endian From (uint32)
//	[4:8]   little-endian To (uint32)
//	[8:12]  length of message type (uint32)
//	[12:16] length of data payload (uint32)
func (r *Router) writeMsg(c net.Conn, env Envelope) {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:], uint32(env.From))
	binary.LittleEndian.PutUint32(header[4:], uint32(env.To))

	mt := []byte(env.Type)
	binary.LittleEndian.PutUint32(header[8:], uint32(len(mt)))
	binary.LittleEndian.PutUint32(header[12:], uint32(len(env.Data)))

	if _, err := c.Write(header); err != nil {
		return
	}
	if _, err := c.Write(mt); err != nil {
		return
	}
	_, _ = c.Write(env.Data)
}

// handleConn continuously reads Envelope messages from a single TCP connection.
// For each full message, it decodes the header, reads the type and payload, and
// forwards the Envelope to inCh for higher-level processing.
func (r *Router) handleConn(conn net.Conn) {
	r.wg.Add(1)
	defer r.wg.Done()
	defer func() {
		// Remove closed connection from tracking, then close it
		r.allMu.Lock()
		delete(r.allConns, conn)
		r.allMu.Unlock()
		_ = conn.Close()
	}()

	reader := bufio.NewReader(conn)

	for {
		select {
		case <-r.stopCh:
			return
		default:
			// Read the fixed-size header (16 bytes)
			h := make([]byte, 16)
			if _, err := io.ReadFull(reader, h); err != nil {
				return
			}
			from := int(binary.LittleEndian.Uint32(h[0:4]))
			to := int(binary.LittleEndian.Uint32(h[4:8]))
			mtLen := binary.LittleEndian.Uint32(h[8:12])
			dLen := binary.LittleEndian.Uint32(h[12:16])

			// Read the message type string
			mt := make([]byte, mtLen)
			if _, err := io.ReadFull(reader, mt); err != nil {
				return
			}
			// Read the data payload
			data := make([]byte, dLen)
			if _, err := io.ReadFull(reader, data); err != nil {
				return
			}

			// Deliver the Envelope to inCh for processing
			select {
			case r.inCh <- Envelope{From: from, To: to, Type: string(mt), Data: data}:
			case <-r.stopCh:
				return
			}
		}
	}
}
