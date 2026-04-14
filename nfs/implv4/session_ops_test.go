package implv4

import (
	"testing"

	"github.com/smallfz/libnfs-go/backend"
	"github.com/smallfz/libnfs-go/fs"
	"github.com/smallfz/libnfs-go/nfs"
	"github.com/smallfz/libnfs-go/xdr"
)

// fakeStat implements just enough of nfs.StatService for the session-op
// handlers, which only touch Backend / CurrentSession / SetCurrentSession.
type fakeStat struct {
	b           *backend.Backend
	currentSess interface{}
	pendingSeq  interface{}
}

func (f *fakeStat) SetCurrentHandle(nfs.FileHandle4)              {}
func (f *fakeStat) CurrentHandle() nfs.FileHandle4                { return nil }
func (f *fakeStat) PushHandle(nfs.FileHandle4)                    {}
func (f *fakeStat) PeekHandle() (nfs.FileHandle4, bool)           { return nil, false }
func (f *fakeStat) PopHandle() (nfs.FileHandle4, bool)            { return nil, false }
func (f *fakeStat) SetClientId(uint64)                            {}
func (f *fakeStat) ClientId() (uint64, bool)                      { return 0, false }
func (f *fakeStat) AddOpenedFile(string, fs.File) uint32          { return 0 }
func (f *fakeStat) GetOpenedFile(uint32) fs.FileOpenState         { return nil }
func (f *fakeStat) FindOpenedFiles(string) []fs.FileOpenState     { return nil }
func (f *fakeStat) RemoveOpenedFile(uint32) fs.FileOpenState      { return nil }
func (f *fakeStat) CloseAndRemoveStallFiles()                     {}
func (f *fakeStat) CleanUp()                                      {}
func (f *fakeStat) Backend() interface{}                          { return f.b }
func (f *fakeStat) CurrentSession() interface{}                   { return f.currentSess }
func (f *fakeStat) SetCurrentSession(v interface{})               { f.currentSess = v }
func (f *fakeStat) PendingSequenceResponse() interface{}          { return f.pendingSeq }
func (f *fakeStat) SetPendingSequenceResponse(v interface{})      { f.pendingSeq = v }

// fakeCtx implements nfs.RPCContext minimally — only Stat() is used by the
// session-op handlers.
type fakeCtx struct {
	stat *fakeStat
}

func (c *fakeCtx) Reader() *xdr.Reader                              { return nil }
func (c *fakeCtx) Writer() *xdr.Writer                              { return nil }
func (c *fakeCtx) Authenticate(*nfs.Auth, *nfs.Auth) (*nfs.Auth, error) { return nil, nil }
func (c *fakeCtx) GetFS() fs.FS                                     { return nil }
func (c *fakeCtx) Stat() nfs.StatService                            { return c.stat }

func newTestCtx() (*fakeCtx, *backend.Backend) {
	b := backend.New(func() fs.FS { return nil }, nil)
	return &fakeCtx{stat: &fakeStat{b: b}}, b
}

func TestExchangeId_SameOwner_SameClientId(t *testing.T) {
	ctx, _ := newTestCtx()
	args := &nfs.EXCHANGE_ID4args{
		ClientOwner: &nfs.ClientOwner4{Verifier: 0xdeadbeef, OwnerId: "owner-A"},
	}
	r1, err := exchangeId(ctx, args)
	if err != nil || r1.Status != nfs.NFS4_OK {
		t.Fatalf("first exchangeId: status=%d err=%v", r1.Status, err)
	}
	r2, err := exchangeId(ctx, args)
	if err != nil || r2.Status != nfs.NFS4_OK {
		t.Fatalf("second exchangeId: status=%d err=%v", r2.Status, err)
	}
	if r1.Ok.ClientId != r2.Ok.ClientId {
		t.Fatalf("expected same clientid for same owner+verifier; got %d vs %d",
			r1.Ok.ClientId, r2.Ok.ClientId)
	}
}

func TestExchangeId_DifferentOwner_DifferentClientId(t *testing.T) {
	ctx, _ := newTestCtx()
	a := &nfs.EXCHANGE_ID4args{ClientOwner: &nfs.ClientOwner4{Verifier: 1, OwnerId: "A"}}
	b := &nfs.EXCHANGE_ID4args{ClientOwner: &nfs.ClientOwner4{Verifier: 1, OwnerId: "B"}}
	r1, _ := exchangeId(ctx, a)
	r2, _ := exchangeId(ctx, b)
	if r1.Ok.ClientId == r2.Ok.ClientId {
		t.Fatalf("expected different clientids for different owners")
	}
}

func TestCreateSession_UnknownClient_StaleClientId(t *testing.T) {
	ctx, _ := newTestCtx()
	args := &nfs.CREATE_SESSION4args{ClientId: 9999}
	res, err := createSession(ctx, args)
	if err != nil {
		t.Fatalf("createSession err: %v", err)
	}
	if res.Status != nfs.NFS4ERR_STALE_CLIENTID {
		t.Fatalf("expected NFS4ERR_STALE_CLIENTID, got %d", res.Status)
	}
}

func TestSequence_UnknownSession_BadSession(t *testing.T) {
	ctx, _ := newTestCtx()
	args := &nfs.SEQUENCE4args{SessionId: [16]byte{0xff, 0xff, 0xff}, SequenceId: 1}
	res, _ := sequence(ctx, args)
	if res.Status != nfs.NFS4ERR_BADSESSION {
		t.Fatalf("expected NFS4ERR_BADSESSION, got %d", res.Status)
	}
}

// helper: drive EXCHANGE_ID + CREATE_SESSION and return the new session id.
func establishSession(t *testing.T, ctx *fakeCtx) [16]byte {
	t.Helper()
	exArgs := &nfs.EXCHANGE_ID4args{
		ClientOwner: &nfs.ClientOwner4{Verifier: 0x1234, OwnerId: "test-owner"},
	}
	exRes, err := exchangeId(ctx, exArgs)
	if err != nil || exRes.Status != nfs.NFS4_OK {
		t.Fatalf("exchangeId: status=%d err=%v", exRes.Status, err)
	}
	csArgs := &nfs.CREATE_SESSION4args{
		ClientId: exRes.Ok.ClientId,
		Sequence: 1,
		ForeChanAttrs: nfs.ChannelAttrs4{
			MaxRequestSize:  1 << 16,
			MaxResponseSize: 1 << 16,
			MaxOperations:   16,
			MaxRequests:     1,
		},
		BackChanAttrs: nfs.ChannelAttrs4{MaxRequests: 1},
	}
	csRes, err := createSession(ctx, csArgs)
	if err != nil || csRes.Status != nfs.NFS4_OK {
		t.Fatalf("createSession: status=%d err=%v", csRes.Status, err)
	}
	return csRes.Ok.SessionId
}

func TestSequence_BadSlot(t *testing.T) {
	ctx, _ := newTestCtx()
	sid := establishSession(t, ctx)
	res, _ := sequence(ctx, &nfs.SEQUENCE4args{SessionId: sid, SequenceId: 1, SlotId: 1})
	if res.Status != nfs.NFS4ERR_BADSLOT {
		t.Fatalf("expected NFS4ERR_BADSLOT, got %d", res.Status)
	}
}

func TestSequence_Progression(t *testing.T) {
	ctx, _ := newTestCtx()
	sid := establishSession(t, ctx)

	r1, _ := sequence(ctx, &nfs.SEQUENCE4args{SessionId: sid, SequenceId: 1})
	if r1.Status != nfs.NFS4_OK {
		t.Fatalf("seq1: expected OK, got %d", r1.Status)
	}
	r2, _ := sequence(ctx, &nfs.SEQUENCE4args{SessionId: sid, SequenceId: 2})
	if r2.Status != nfs.NFS4_OK {
		t.Fatalf("seq2: expected OK, got %d", r2.Status)
	}
	// Skipping ahead by 2 must misorder.
	r4, _ := sequence(ctx, &nfs.SEQUENCE4args{SessionId: sid, SequenceId: 4})
	if r4.Status != nfs.NFS4ERR_SEQ_MISORDERED {
		t.Fatalf("seq4: expected NFS4ERR_SEQ_MISORDERED, got %d", r4.Status)
	}
}

func TestDestroySession_Idempotent(t *testing.T) {
	ctx, _ := newTestCtx()
	sid := establishSession(t, ctx)
	r1, _ := destroySession(ctx, &nfs.DESTROY_SESSION4args{SessionId: sid})
	if r1.Status != nfs.NFS4_OK {
		t.Fatalf("first destroy: %d", r1.Status)
	}
	// Second call on a now-unknown id should still be OK.
	r2, _ := destroySession(ctx, &nfs.DESTROY_SESSION4args{SessionId: sid})
	if r2.Status != nfs.NFS4_OK {
		t.Fatalf("second destroy: %d", r2.Status)
	}
}
