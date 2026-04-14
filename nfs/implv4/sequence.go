package implv4

import (
	"github.com/smallfz/libnfs-go/backend"
	"github.com/smallfz/libnfs-go/nfs"
)

// sequence implements SEQUENCE (RFC 5661 §18.46) — forward path only.
// Replay short-circuiting lives in the compound dispatcher; this handler is
// only reached for fresh sequence ids.
func sequence(x nfs.RPCContext, args *nfs.SEQUENCE4args) (*nfs.SEQUENCE4res, error) {
	bAny := x.Stat().Backend()
	b, ok := bAny.(*backend.Backend)
	if !ok || b == nil {
		return &nfs.SEQUENCE4res{Status: nfs.NFS4ERR_SERVERFAULT}, nil
	}
	reg := b.Registry()

	sess, found := reg.LookupSession(args.SessionId)
	if !found {
		return &nfs.SEQUENCE4res{Status: nfs.NFS4ERR_BADSESSION}, nil
	}
	if args.SlotId != 0 {
		// We advertised MaxRequests=1; only slot 0 is valid.
		return &nfs.SEQUENCE4res{Status: nfs.NFS4ERR_BADSLOT}, nil
	}

	slot := &sess.Slots[0]
	slot.Mu.Lock()
	defer slot.Mu.Unlock()

	expected := slot.SeqId + 1
	if args.SequenceId != expected {
		return &nfs.SEQUENCE4res{Status: nfs.NFS4ERR_SEQ_MISORDERED}, nil
	}
	slot.SeqId = args.SequenceId
	slot.CacheHit = false

	x.Stat().SetCurrentSession(sess)

	return &nfs.SEQUENCE4res{
		Status: nfs.NFS4_OK,
		Ok: &nfs.SEQUENCE4resok{
			SessionId:           sess.Id,
			SequenceId:          args.SequenceId,
			SlotId:              0,
			HighestSlotId:       0,
			TargetHighestSlotId: 0,
			StatusFlags:         0,
		},
	}, nil
}
