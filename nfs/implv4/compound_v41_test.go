// compound_v41_test.go
//
// NOTE: The plan called for a full raw-XDR compound dispatcher test with a
// hand-built buffer containing [PUTROOTFH, GETATTR] at minorVer=1 to exercise
// the SEQUENCE-first enforcement path, then the same compound prefixed with
// SEQUENCE for the happy path. Building those XDR buffers from scratch turned
// out to be fragile — the existing compound_test.go only DECODES captured
// kernel traces, it has no encoder helpers — so per the plan's escape hatch we
// drive the v4.1 state machine end-to-end at the handler layer instead. This
// covers EXCHANGE_ID -> CREATE_SESSION -> multiple SEQUENCE -> DESTROY_SESSION.
// SEQUENCE-first enforcement in compound.go is exercised by Stream D's kernel
// mount integration tests in the gateway repo.

package implv4

import (
	"testing"

	"github.com/smallfz/libnfs-go/nfs"
)

func TestV41StateMachine_HappyPath(t *testing.T) {
	ctx, _ := newTestCtx()

	// EXCHANGE_ID
	exRes, err := exchangeId(ctx, &nfs.EXCHANGE_ID4args{
		ClientOwner: &nfs.ClientOwner4{Verifier: 0xCAFEBABE, OwnerId: "kernel-client"},
	})
	if err != nil || exRes.Status != nfs.NFS4_OK {
		t.Fatalf("EXCHANGE_ID failed: status=%d err=%v", exRes.Status, err)
	}
	if exRes.Ok.ClientId == 0 {
		t.Fatalf("EXCHANGE_ID returned zero clientid")
	}
	if (exRes.Ok.Flags & nfs.EXCHGID4_FLAG_USE_NON_PNFS) == 0 {
		t.Fatalf("expected USE_NON_PNFS flag in EXCHANGE_ID reply")
	}

	// CREATE_SESSION
	csRes, err := createSession(ctx, &nfs.CREATE_SESSION4args{
		ClientId: exRes.Ok.ClientId,
		Sequence: 1,
		ForeChanAttrs: nfs.ChannelAttrs4{
			MaxRequestSize:  1 << 20,
			MaxResponseSize: 1 << 20,
			MaxOperations:   128,
			MaxRequests:     16,
		},
		BackChanAttrs: nfs.ChannelAttrs4{MaxRequests: 1},
	})
	if err != nil || csRes.Status != nfs.NFS4_OK {
		t.Fatalf("CREATE_SESSION failed: status=%d err=%v", csRes.Status, err)
	}
	// Server caps MaxOperations at 64 and MaxRequests at 1.
	if csRes.Ok.ForeChanAttrs.MaxOperations != 64 {
		t.Fatalf("expected MaxOperations=64, got %d", csRes.Ok.ForeChanAttrs.MaxOperations)
	}
	if csRes.Ok.ForeChanAttrs.MaxRequests != 1 {
		t.Fatalf("expected MaxRequests=1, got %d", csRes.Ok.ForeChanAttrs.MaxRequests)
	}

	sid := csRes.Ok.SessionId

	// SEQUENCE x 3
	for i := uint32(1); i <= 3; i++ {
		r, _ := sequence(ctx, &nfs.SEQUENCE4args{SessionId: sid, SequenceId: i})
		if r.Status != nfs.NFS4_OK {
			t.Fatalf("SEQUENCE seqid=%d: status=%d", i, r.Status)
		}
		if ctx.Stat().CurrentSession() == nil {
			t.Fatalf("SEQUENCE seqid=%d: CurrentSession not set", i)
		}
	}

	// DESTROY_SESSION
	dsRes, _ := destroySession(ctx, &nfs.DESTROY_SESSION4args{SessionId: sid})
	if dsRes.Status != nfs.NFS4_OK {
		t.Fatalf("DESTROY_SESSION failed: %d", dsRes.Status)
	}

	// Subsequent SEQUENCE on the dead session should hit BADSESSION.
	r, _ := sequence(ctx, &nfs.SEQUENCE4args{SessionId: sid, SequenceId: 4})
	if r.Status != nfs.NFS4ERR_BADSESSION {
		t.Fatalf("post-destroy SEQUENCE: expected BADSESSION, got %d", r.Status)
	}
}

func TestV41_DestroyClientId_CascadesSessions(t *testing.T) {
	ctx, _ := newTestCtx()
	exRes, _ := exchangeId(ctx, &nfs.EXCHANGE_ID4args{
		ClientOwner: &nfs.ClientOwner4{Verifier: 1, OwnerId: "x"},
	})
	csRes, _ := createSession(ctx, &nfs.CREATE_SESSION4args{
		ClientId:      exRes.Ok.ClientId,
		Sequence:      1,
		ForeChanAttrs: nfs.ChannelAttrs4{MaxRequests: 1},
		BackChanAttrs: nfs.ChannelAttrs4{MaxRequests: 1},
	})
	sid := csRes.Ok.SessionId

	dc, _ := destroyClientId(ctx, &nfs.DESTROY_CLIENTID4args{ClientId: exRes.Ok.ClientId})
	if dc.Status != nfs.NFS4_OK {
		t.Fatalf("DESTROY_CLIENTID: %d", dc.Status)
	}

	r, _ := sequence(ctx, &nfs.SEQUENCE4args{SessionId: sid, SequenceId: 1})
	if r.Status != nfs.NFS4ERR_BADSESSION {
		t.Fatalf("expected cascade to drop session, got status=%d", r.Status)
	}
}
