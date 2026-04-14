package implv4

import (
	"testing"

	"github.com/smallfz/libnfs-go/backend"
	"github.com/smallfz/libnfs-go/nfs"
)

// TestReplayCache_HitOnSameSeqid drives the SessionRegistry directly
// to verify that lookupReplay returns the cached body when the slot
// has been populated by a prior compound and the incoming SEQUENCE
// uses the same seqid.
func TestReplayCache_HitOnSameSeqid(t *testing.T) {
	b := backend.New(nil, nil)
	reg := b.Registry()

	// Establish a client + session by hand.
	client, _ := reg.ExchangeId([]byte("owner"), [8]byte{1, 2, 3})
	if err := reg.ConfirmClient(client.Id); err != nil {
		t.Fatalf("ConfirmClient: %v", err)
	}
	sess, err := reg.CreateSession(client.Id, backend.ChannelAttrs{}, backend.ChannelAttrs{})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Pretend a forward compound landed at seqid=7 and cached its body.
	slot := &sess.Slots[0]
	slot.Mu.Lock()
	slot.SeqId = 7
	slot.Cached = []byte{0xAA, 0xBB, 0xCC}
	slot.Mu.Unlock()

	ctx := &fakeCtx{stat: &fakeStat{b: b}}

	// Same seqid → replay hit.
	args := &nfs.SEQUENCE4args{SessionId: sess.Id, SequenceId: 7}
	got, hit := lookupReplay(ctx, args)
	if !hit {
		t.Fatalf("expected replay hit")
	}
	if string(got) != string([]byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("cached body mismatch: %x", got)
	}

	// Different seqid → no hit.
	args.SequenceId = 8
	if _, hit := lookupReplay(ctx, args); hit {
		t.Fatalf("did not expect replay hit on fresh seqid")
	}

	// Unknown session → no hit.
	bogus := &nfs.SEQUENCE4args{SessionId: [16]byte{0xEE}, SequenceId: 7}
	if _, hit := lookupReplay(ctx, bogus); hit {
		t.Fatalf("did not expect hit on bogus session")
	}
}

func TestReplayCache_NoCacheReturnsMiss(t *testing.T) {
	b := backend.New(nil, nil)
	reg := b.Registry()
	client, _ := reg.ExchangeId([]byte("o"), [8]byte{})
	reg.ConfirmClient(client.Id)
	sess, _ := reg.CreateSession(client.Id, backend.ChannelAttrs{}, backend.ChannelAttrs{})

	ctx := &fakeCtx{stat: &fakeStat{b: b}}
	args := &nfs.SEQUENCE4args{SessionId: sess.Id, SequenceId: 1}
	if _, hit := lookupReplay(ctx, args); hit {
		t.Fatalf("fresh slot should not have a cached body")
	}
}
