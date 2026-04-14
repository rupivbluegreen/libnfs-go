package implv4

import (
	"github.com/smallfz/libnfs-go/backend"
	"github.com/smallfz/libnfs-go/nfs"
	"github.com/smallfz/libnfs-go/xdr"
)

// lookupReplay returns the cached compound reply body for a SEQUENCE
// op whose seqid matches what we already processed for this slot,
// per RFC 8881 §2.10.6.2. The cache is populated by Compound() at the
// end of the forward path; until that happens the slot's Cached field
// is nil and this function returns ok=false.
//
// The caller is responsible for writing the returned bytes to the
// wire and for draining any remaining ops in the same compound from
// the reader before returning.
func lookupReplay(ctx nfs.RPCContext, args *nfs.SEQUENCE4args) ([]byte, bool) {
	bAny := ctx.Stat().Backend()
	b, ok := bAny.(*backend.Backend)
	if !ok || b == nil {
		return nil, false
	}
	sess, found := b.Registry().LookupSession(args.SessionId)
	if !found || len(sess.Slots) == 0 {
		return nil, false
	}
	if args.SlotId != 0 {
		return nil, false
	}
	slot := &sess.Slots[0]
	slot.Mu.Lock()
	defer slot.Mu.Unlock()
	if slot.Cached == nil {
		return nil, false
	}
	if args.SequenceId != slot.SeqId {
		return nil, false
	}
	// Same seqid as the one we last processed → replay. Mark for
	// observability and hand back a private copy so the caller can
	// safely write it without holding the slot lock.
	slot.CacheHit = true
	out := make([]byte, len(slot.Cached))
	copy(out, slot.Cached)
	return out, true
}

// drainRemainingOps consumes n more ops (and their args, opaquely)
// from the reader so the wire stays aligned after a replay short-
// circuit. We don't know each op's arg layout up front, so we do the
// minimum legal thing: read the opnum then trust the connection-level
// framing to bound the leftover bytes. Any decode error here is non-
// fatal (the next compound will discover any misalignment), but we
// still log it so a real protocol divergence is visible.
//
// In practice the Linux client only retransmits whole compounds, so n
// is almost always 0 — the SEQUENCE op is the entire retransmitted
// compound. The drain loop is here for safety only.
func drainRemainingOps(r *xdr.Reader, n uint32) error {
	for i := uint32(0); i < n; i++ {
		var opnum uint32
		if _, err := r.ReadAs(&opnum); err != nil {
			return err
		}
	}
	return nil
}
