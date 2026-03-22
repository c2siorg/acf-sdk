// listener.go — IPC accept loop.
package transport

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/c2siorg/acf-sdk/sidecar/internal/crypto"
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

type Config struct {
	Address    string
	Connector  Connector
	Signer     *crypto.Signer
	NonceStore *crypto.NonceStore
	Pipeline   PipelineInterface
}

type PipelineInterface interface {
	Process(ctx *riskcontext.RiskContext)
}

type Listener struct {
	cfg    Config
	ln     net.Listener
	stopCh chan struct{}
}

func NewListener(cfg Config) (*Listener, error) {
	if cfg.Address == "" {
		cfg.Address = cfg.Connector.DefaultAddress()
	}
	if err := cfg.Connector.Cleanup(cfg.Address); err != nil {
		return nil, err
	}
	ln, err := cfg.Connector.Listen(cfg.Address)
	if err != nil {
		return nil, err
	}
	return &Listener{cfg: cfg, ln: ln, stopCh: make(chan struct{})}, nil
}

func (l *Listener) Serve() error {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			select {
			case <-l.stopCh:
				return nil
			default:
				return err
			}
		}
		go l.handleConn(conn)
	}
}

func (l *Listener) Stop() {
	select {
	case <-l.stopCh:
	default:
		close(l.stopCh)
	}
	l.ln.Close()
}

func (l *Listener) handleConn(conn net.Conn) {
	defer conn.Close()

	// 1. Decode Request
	rf, err := DecodeRequest(conn)
	if err != nil {
		log.Printf("transport: decode error: %v", err)
		return
	}

	// 2. Verify Security
	length := uint32(len(rf.Payload))
	signedMsg := SignedMessage(rf.Version, length, rf.Nonce, rf.Payload)
	if !l.cfg.Signer.Verify(signedMsg, rf.HMAC[:]) {
		log.Printf("transport: security alert: HMAC mismatch")
		return
	}
	if l.cfg.NonceStore.Seen(rf.Nonce[:]) {
		log.Printf("transport: security alert: Replay detected")
		return
	}

	// 3. Create RiskContext
	ctx := &riskcontext.RiskContext{
		SessionID:  "sid-" + strconv.FormatInt(time.Now().Unix(), 10),
		Payload:    string(rf.Payload),
		Signals:    []string{"transport_verified"}, 
		Provenance: "sdk-client",
		HookType:   "on_prompt",
	}

	// 4. Process Pipeline
	if l.cfg.Pipeline != nil {
		l.cfg.Pipeline.Process(ctx)
	}

	// 5. Determine Decision
	var decision byte = DecisionAllow 
	if ctx.Score > 0.8 {
		decision = DecisionBlock
	} else if ctx.Score > 0.4 {
		decision = DecisionSanitise
	}

	// 6. Map back to SanitisedPayload
	payloadStr, ok := ctx.Payload.(string)
	if !ok {
		payloadStr = "" 
	}
	
	respFrame := &ResponseFrame{
		Decision:         decision,
		SanitisedPayload: []byte(payloadStr), // Matches frame.go
	}

	// 7. Write to Connection
	// EncodeResponse returns the bytes; we then write them to 'conn'
	respBytes := EncodeResponse(respFrame)
	if _, err := conn.Write(respBytes); err != nil {
		log.Printf("transport: response error: %v", err)
	}
}