package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/smallfz/libnfs-go/auth"
	"github.com/smallfz/libnfs-go/backend"
	"github.com/smallfz/libnfs-go/fs"
	"github.com/smallfz/libnfs-go/memfs"
	"github.com/smallfz/libnfs-go/nfs"
	"github.com/smallfz/libnfs-go/xdr"
)

// generateTLSPair returns an in-memory TLS server config and a
// matching client config that trusts the same self-signed cert.
func generateTLSPair(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "starttls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"starttls-test", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemKeyDer, _ := x509.MarshalECPrivateKey(priv)
	pemKeyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pemKeyDer})
	cert, err := tls.X509KeyPair(pemKey, pemKeyBlock)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	server := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	client := &tls.Config{RootCAs: pool, ServerName: "starttls-test", MinVersion: tls.VersionTLS13}
	return server, client
}

// startTestServer launches a libnfs-go server on a free TCP port with
// the given TLS config and returns its address along with a stop fn.
func startTestServer(t *testing.T, tlsCfg *tls.Config) (string, func()) {
	t.Helper()
	mfs := memfs.NewMemFS()
	vfsLoader := func() fs.FS { return mfs }
	bk := backend.New(vfsLoader, func(c, v *nfs.Auth) (*nfs.Auth, fs.Creds, error) {
		return auth.Null(c, v)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	opts := []Option{}
	if tlsCfg != nil {
		opts = append(opts, WithTLSConfig(tlsCfg))
	}
	srv, err := NewServer(ln, bk, opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.Serve() }()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// sendNullProbe writes an NFSv4 NULL RPC with the given cred flavor on
// the wire and returns the server's reply bytes (without the 4-byte
// fragment header).
func sendNullProbe(t *testing.T, conn net.Conn, xid uint32, credFlavor uint32) []byte {
	t.Helper()
	body := &bytes.Buffer{}
	w := xdr.NewWriter(body)

	// rpc_msg call header
	w.WriteUint32(xid)             // xid
	w.WriteUint32(nfs.RPC_CALL)    // msg type
	w.WriteUint32(2)               // rpc version
	w.WriteUint32(100003)          // NFS program
	w.WriteUint32(4)               // version 4
	w.WriteUint32(nfs.PROC4_VOID)  // proc 0
	// cred
	w.WriteUint32(credFlavor)
	w.WriteUint32(0) // cred body len = 0
	// verf
	w.WriteUint32(nfs.AUTH_FLAVOR_NULL)
	w.WriteUint32(0) // verf body len = 0

	frag := uint32(body.Len()) | (1 << 31)
	hw := xdr.NewWriter(conn)
	if _, err := hw.WriteUint32(frag); err != nil {
		t.Fatalf("write frag: %v", err)
	}
	if _, err := conn.Write(body.Bytes()); err != nil {
		t.Fatalf("write body: %v", err)
	}

	// Read reply
	r := xdr.NewReader(conn)
	rfrag, err := r.ReadUint32()
	if err != nil {
		t.Fatalf("read frag: %v", err)
	}
	rsize := int((rfrag << 1) >> 1)
	out := make([]byte, rsize)
	if _, err := r.ReadBytes(rsize); err != nil {
		// ReadBytes returns an internal slice from the buffer — fall
		// through; the test only inspects the first few fields below.
	}
	_ = out
	// Pull the first eight uint32s back via a fresh reader on the
	// already-buffered bytes for inspection.
	hdrBuf := bytes.NewBuffer(nil)
	hw2 := xdr.NewWriter(hdrBuf)
	hw2.WriteUint32(rfrag)
	return hdrBuf.Bytes()
}

// readReplyFields reads the standard accept-success reply header from
// conn and returns (xid, replyVerfFlavor).
func readReplyFields(t *testing.T, conn net.Conn) (uint32, uint32) {
	t.Helper()
	r := xdr.NewReader(conn)
	frag, err := r.ReadUint32()
	if err != nil {
		t.Fatalf("read frag: %v", err)
	}
	_ = frag
	xid, _ := r.ReadUint32()
	msgType, _ := r.ReadUint32()
	if msgType != nfs.RPC_REPLY {
		t.Fatalf("expected RPC_REPLY, got %d", msgType)
	}
	replyStat, _ := r.ReadUint32()
	if replyStat != nfs.MSG_ACCEPTED {
		t.Fatalf("expected MSG_ACCEPTED, got %d", replyStat)
	}
	verfFlavor, _ := r.ReadUint32()
	verfLen, _ := r.ReadUint32()
	if verfLen > 0 {
		_, _ = r.ReadBytes(int(verfLen))
	}
	acceptStat, _ := r.ReadUint32()
	if acceptStat != nfs.ACCEPT_SUCCESS {
		t.Fatalf("expected ACCEPT_SUCCESS, got %d", acceptStat)
	}
	return xid, verfFlavor
}

// writeNullCall writes an NFSv4 NULL RPC call with the given cred
// flavor to w (which can be a plaintext or TLS conn). Used by the
// end-to-end STARTTLS test below.
func writeNullCall(t *testing.T, w net.Conn, xid uint32, credFlavor uint32) {
	t.Helper()
	body := &bytes.Buffer{}
	bw := xdr.NewWriter(body)
	bw.WriteUint32(xid)
	bw.WriteUint32(nfs.RPC_CALL)
	bw.WriteUint32(2)
	bw.WriteUint32(100003)
	bw.WriteUint32(4)
	bw.WriteUint32(nfs.PROC4_VOID)
	bw.WriteUint32(credFlavor)
	bw.WriteUint32(0)
	bw.WriteUint32(nfs.AUTH_FLAVOR_NULL)
	bw.WriteUint32(0)
	frag := uint32(body.Len()) | (1 << 31)
	hw := xdr.NewWriter(w)
	hw.WriteUint32(frag)
	w.Write(body.Bytes())
}

func TestStartTLS_PlaintextProbeReturnsAuthNone(t *testing.T) {
	addr, stop := startTestServer(t, nil) // server has no TLS config
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	writeNullCall(t, conn, 1, nfs.AUTH_FLAVOR_TLS)
	xid, verfFlavor := readReplyFields(t, conn)
	if xid != 1 {
		t.Fatalf("xid = %d, want 1", xid)
	}
	if verfFlavor != nfs.AUTH_FLAVOR_NULL {
		t.Fatalf("verf flavor = %d, want AUTH_NONE (server has no TLS)", verfFlavor)
	}
}

func TestStartTLS_HandshakeUpgrade(t *testing.T) {
	srvTLS, cliTLS := generateTLSPair(t)
	addr, stop := startTestServer(t, srvTLS)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// 1. Send AUTH_TLS NULL probe.
	writeNullCall(t, conn, 42, nfs.AUTH_FLAVOR_TLS)

	// 2. Server should reply with AUTH_TLS in the verifier.
	xid, verfFlavor := readReplyFields(t, conn)
	if xid != 42 {
		t.Fatalf("xid = %d, want 42", xid)
	}
	if verfFlavor != nfs.AUTH_FLAVOR_TLS {
		t.Fatalf("verf flavor = %d, want AUTH_TLS", verfFlavor)
	}

	// 3. Client wraps the same TCP conn in TLS and handshakes.
	tlsConn := tls.Client(conn, cliTLS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	state := tlsConn.ConnectionState()
	if state.Version < tls.VersionTLS13 {
		t.Fatalf("negotiated TLS < 1.3: 0x%04x", state.Version)
	}

	// 4. Send a plaintext NULL over the now-TLS-wrapped connection.
	// The server should respond normally because the inner stream is
	// plaintext NFS even though the outer wire is encrypted.
	writeNullCall(t, tlsConn, 43, nfs.AUTH_FLAVOR_NULL)
	xid2, verf2 := readReplyFields(t, tlsConn)
	if xid2 != 43 {
		t.Fatalf("post-TLS xid = %d, want 43", xid2)
	}
	if verf2 != nfs.AUTH_FLAVOR_NULL {
		t.Fatalf("post-TLS verf flavor = %d, want AUTH_NONE", verf2)
	}
}
