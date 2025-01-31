package tapdtest

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/lndtest"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

type Config struct {
	Args    []string
	BinPath string

	Stderr io.Writer
	Stdout io.Writer

	Dir   string
	Chain *chaincfg.Params

	RPCAddresses  []string
	RESTAddresses []string
}

type Harness struct {
	*grpc.ClientConn

	cfg *Config
	cmd *exec.Cmd

	rpc  string
	rest string

	mac  []byte
	cert []byte
}

func (h *Harness) RPCAddress() string {
	return h.rpc
}

func (h *Harness) AdminMacPath() string {
	return filepath.Join(h.cfg.Dir, "data", nameParams(h.cfg.Chain), "admin.macaroon")
}

func (h *Harness) AdminMac() []byte {
	return h.mac
}

func (h *Harness) TLSCertPath() string {
	return filepath.Join(h.cfg.Dir, "tls.cert")
}

func (h *Harness) TLSCert() []byte {
	return h.cert
}

func (h *Harness) dial() error {
	tlsCred, err := credentials.NewClientTLSFromFile(filepath.Join(h.cfg.Dir, "tls.cert"), "")
	if err != nil {
		return err
	}

	b, err := os.ReadFile(h.AdminMacPath())
	if err != nil {
		return err
	}

	mac := &macaroon.Macaroon{}

	err = mac.UnmarshalBinary(b)
	if err != nil {
		return err
	}

	macCred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return err
	}

	h.ClientConn, err = grpc.Dial(h.rpc,
		grpc.WithTransportCredentials(tlsCred),
		grpc.WithPerRPCCredentials(macCred),
	)
	if err != nil {
		return err
	}

	return nil
}

func (h *Harness) Start() {
	name := h.cfg.BinPath
	if name == "" {
		name = "tapd"
	}

	h.cmd = exec.Command(name, h.cfg.Args...)

	pr, pw, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	h.cmd.Stderr = h.cfg.Stderr
	h.cmd.Stdout = pw

	err = h.cmd.Start()
	if err != nil {
		panic(err)
	}

	var r io.Reader = pr

	// Pipe the early output to stdout if configured.
	if h.cfg.Stdout != nil {
		r = io.TeeReader(pr, h.cfg.Stdout)
	}

	// Scan the stdout line by line.
	scan := bufio.NewScanner(r)

	// Scan for the RPC & REST (gRPC proxy) to be listening.
	for scan.Scan() && (h.rpc == "" || h.rest == "") {
		line := scan.Text()

		_, addr, ok := strings.Cut(line, "RPC server listening on ")
		if ok {
			h.rpc = addr
			continue
		}

		_, addr, ok = strings.Cut(line, "gRPC proxy started at ")
		if ok {
			h.rest = addr
			continue
		}
	}

	// Discard as a fallback.
	stdout := io.Discard

	// Use the configured stdout by default.
	if h.cfg.Stdout != nil {
		stdout = h.cfg.Stdout
	}

	// The pipe needs to continuously be read, otherwise `btcd` will hang.
	go io.Copy(stdout, pr)

	start := time.Now()

	for time.Since(start) < 30*time.Second {
		err = h.dial()
		if err != nil {
			continue
		}

		err = nil
		break
	}

	if h.ClientConn == nil {
		panic("timeout")
	}

	if err != nil {
		panic(fmt.Sprintf("timeout: last error: %v", err))
	}

	h.cert, err = os.ReadFile(h.TLSCertPath())
	if err != nil {
		panic(err)
	}

	h.mac, err = os.ReadFile(h.AdminMacPath())
	if err != nil {
		panic(err)
	}
}

func (h *Harness) Stop() error {
	return h.cmd.Process.Kill()
}

type optFunc = func(*Config)

func WithArgs(args ...string) optFunc {
	return func(cfg *Config) {
		cfg.Args = append(cfg.Args, args...)
	}
}

func WithDir(dir string) optFunc {
	return func(cfg *Config) {
		cfg.Dir = dir
	}
}

func WithLND(lnd *lndtest.Harness) optFunc {
	return func(cfg *Config) {
		cfg.Args = append(cfg.Args,
			"--lnd.host", lnd.RPCAddress(),
			"--lnd.macaroonpath", lnd.AdminMacPath(),
			"--lnd.tlspath", lnd.TLSCertPath(),
		)
	}
}

func WithChainParams(chain *chaincfg.Params) optFunc {
	return func(cfg *Config) {
		cfg.Chain = chain
	}
}

// Append a REST address.
func WithRESTAddress(addr string) optFunc {
	return func(cfg *Config) {
		cfg.RESTAddresses = append(cfg.RESTAddresses, addr)
	}
}

// Append a RPC address.
func WithRPCAddress(addr string) optFunc {
	return func(cfg *Config) {
		cfg.RPCAddresses = append(cfg.RPCAddresses, addr)
	}
}

// Update the output.
func WithOutput(stderr io.Writer, stdout io.Writer) func(*Config) {
	return func(cfg *Config) {
		cfg.Stderr = stderr
		cfg.Stdout = stdout
	}
}

func New(opts ...optFunc) *Harness {
	h := NewUnstarted(opts...)
	h.Start()

	return h
}

func NewUnstarted(opts ...optFunc) *Harness {
	// Create a temporary directory.
	tmp, err := os.MkdirTemp("", "tapdtest-*")
	if err != nil {
		panic(err)
	}

	cfg := &Config{
		// Use simnet by default.
		Chain: &chaincfg.SimNetParams,
		Dir:   tmp,

		// Use port zero by default to allocate a random port.
		RPCAddresses:  []string{"127.0.0.1:0"},
		RESTAddresses: []string{"127.0.0.1:0"},
	}

	for _, opt := range opts {
		opt(cfg)
	}

	cfg.Args = append(cfg.Args,
		"--network", nameParams(cfg.Chain),
		"--tapddir", cfg.Dir,
	)

	// Set all the REST addresses.
	for _, addr := range cfg.RESTAddresses {
		cfg.Args = append(cfg.Args, "--restlisten", addr)
	}

	// Set all the RPC addresses.
	for _, addr := range cfg.RPCAddresses {
		cfg.Args = append(cfg.Args, "--rpclisten", addr)
	}

	return &Harness{
		cfg: cfg,
	}
}

// `btcd` refers to testnet3 as "testnet", match behaviour here.
// https://github.com/btcsuite/btcd/blob/cd05d9ad3d0597368adf95c54bdc530700393aed/params.go#L73-L89
func nameParams(chain *chaincfg.Params) string {
	var name string

	switch chain.Name {
	case chaincfg.TestNet3Params.Name:
		name = "testnet"

	default:
		name = chain.Name
	}

	return name
}
