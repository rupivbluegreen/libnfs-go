package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/smallfz/libnfs-go/log"
	"github.com/smallfz/libnfs-go/nfs"
	"github.com/smallfz/libnfs-go/xdr"
)

type SessionMux interface {
	HandleProc(*nfs.RPCMsgCall) (int, error)
}

type rpcHeader struct {
	Xid  uint32
	Type uint32
}

type Session struct {
	conn      net.Conn
	backend   nfs.Backend
	tlsConfig *tls.Config
	reader    *xdr.Reader
	tlsActive bool
}

func (sess *Session) sendResponse(dat []byte) error {
	frag := uint32(len(dat)) | uint32(1<<31)
	writer := xdr.NewWriter(sess.conn)
	if _, err := writer.WriteUint32(frag); err != nil {
		return err
	}
	if _, err := writer.Write(dat); err != nil {
		return err
	}
	return nil
}

func (sess *Session) Conn() net.Conn {
	return sess.conn
}

func (sess *Session) Start(ctx context.Context) error {
	defer func() {
		sess.conn.Close()
		log.Debugf("Disconnected from %v.", sess.conn.RemoteAddr())
	}()

	backendSession := sess.backend.CreateSession(sess)
	defer backendSession.Close()

	auth := backendSession.Authentication()
	vfs := backendSession.GetFS()
	stat := backendSession.GetStatService()

	sess.reader = xdr.NewReader(sess.conn)

	for {
		reader := sess.reader
		frag, err := reader.ReadUint32()
		if err != nil {
			if err == io.EOF {
				return nil
			}
		}

		if frag&(1<<31) == 0 {
			return errors.New("(!)ignored: fragmented request")
		}

		headerSize := (frag << 1) >> 1
		restSize := int(headerSize)

		header := &nfs.RPCMsgCall{}
		if size, err := reader.ReadAs(header); err != nil {
			return fmt.Errorf("ReadAs(%T): %v", header, err)
		} else {
			restSize -= size
		}

		if header.MsgType != nfs.RPC_CALL {
			return errors.New("expecting a rpc call message")
		}

		// RFC 9289: a NULL probe with cred.flavor == AUTH_TLS asks
		// whether the server can do in-band STARTTLS. We answer per
		// the RFC, then either upgrade the connection in place or
		// signal "no TLS" so the client falls back to plaintext.
		if header.Proc == nfs.PROC4_VOID && header.Cred != nil &&
			header.Cred.Flavor == nfs.AUTH_FLAVOR_TLS && !sess.tlsActive {
			if err := sess.handleStartTLS(header, restSize); err != nil {
				return err
			}
			continue
		}

		// log.Infof("header: %v", header)

		mux := (SessionMux)(nil)

		buff := bytes.NewBuffer([]byte{})
		writer := xdr.NewWriter(buff)

		switch header.Vers {
		case 4:
			mux = &Muxv4{
				reader: reader,
				writer: writer,
				auth:   auth,
				fs:     vfs,
				stat:   stat,
			}

		case 3:
			mux = &Mux{
				reader: reader,
				writer: writer,
				auth:   auth,
				fs:     vfs,
				stat:   stat,
			}

		default:
			seq := []interface{}{
				&nfs.RPCMsgReply{
					Xid:       header.Xid,
					MsgType:   nfs.RPC_REPLY,
					ReplyStat: nfs.MSG_ACCEPTED,
				},
				nfs.NewEmptyAuth(),
				nfs.ACCEPT_PROG_MISMATCH,
				uint32(3), // low:  v3
				uint32(4), // high: v4
			}
			for _, v := range seq {
				if _, err := writer.WriteAny(v); err != nil {
					return err
				}
			}
		}

		if mux != nil {
			if size, err := mux.HandleProc(header); err != nil {
				return fmt.Errorf("mux.HandlerProc(%d): %v", header.Proc, err)
			} else {
				restSize -= size
			}
		} else {
			return errors.New("invalid rpc message: no suitable mux")
		}

		if err := sess.sendResponse(buff.Bytes()); err != nil {
			return fmt.Errorf("sendResponse: %v", err)
		}

		if restSize > 0 {
			log.Warnf("%d bytes unread.", restSize)
			if _, err := reader.ReadBytes(restSize); err != nil {
				if err == io.EOF {
					return nil
				}
			}
		}
	}
}

func handleSession(ctx context.Context, backend nfs.Backend, conn net.Conn, tlsConfig *tls.Config) error {
	sess := &Session{
		conn:      conn,
		backend:   backend,
		tlsConfig: tlsConfig,
	}
	return sess.Start(ctx)
}

// handleStartTLS handles the RFC 9289 in-band STARTTLS upgrade
// triggered by a NULL probe with AUTH_TLS in cred. The probe must
// contain no body other than the standard PROC4_VOID args (zero
// bytes). On a TLS-enabled server we reply with AUTH_TLS in the
// verifier and immediately wrap the connection in tls.Server. On a
// plaintext-only server we reply with AUTH_NONE so the client falls
// back gracefully.
func (sess *Session) handleStartTLS(header *nfs.RPCMsgCall, restSize int) error {
	// Drain any unread args bytes so the wire stays aligned. PROC4_VOID
	// has no body; restSize should already be zero, but be defensive.
	if restSize > 0 {
		if _, err := sess.reader.ReadBytes(restSize); err != nil && err != io.EOF {
			return fmt.Errorf("startTLS drain: %w", err)
		}
	}

	// Build the canned reply: success with verifier set to either
	// AUTH_TLS (we will upgrade) or AUTH_NONE (please fall back).
	verfFlavor := nfs.AUTH_FLAVOR_NULL
	upgrade := false
	if sess.tlsConfig != nil {
		verfFlavor = nfs.AUTH_FLAVOR_TLS
		upgrade = true
	}

	buff := bytes.NewBuffer(nil)
	w := xdr.NewWriter(buff)
	rh := &nfs.RPCMsgReply{
		Xid:       header.Xid,
		MsgType:   nfs.RPC_REPLY,
		ReplyStat: nfs.MSG_ACCEPTED,
	}
	if _, err := w.WriteAny(rh); err != nil {
		return err
	}
	if _, err := w.WriteAny(&nfs.Auth{Flavor: verfFlavor, Body: []byte{}}); err != nil {
		return err
	}
	if _, err := w.WriteUint32(nfs.ACCEPT_SUCCESS); err != nil {
		return err
	}
	// PROC4_VOID returns no body.
	if err := sess.sendResponse(buff.Bytes()); err != nil {
		return fmt.Errorf("startTLS reply: %w", err)
	}

	if !upgrade {
		log.Debugf("startTLS: server has no TLS config, replied AUTH_NONE")
		return nil
	}

	log.Infof("startTLS: upgrading connection from %v to TLS",
		sess.conn.RemoteAddr())
	tlsConn := tls.Server(sess.conn, sess.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("startTLS handshake: %w", err)
	}
	sess.conn = tlsConn
	sess.reader = xdr.NewReader(tlsConn)
	sess.tlsActive = true
	log.Infof("startTLS: handshake complete (cipher=%s, ver=0x%04x)",
		tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite),
		tlsConn.ConnectionState().Version)
	return nil
}
