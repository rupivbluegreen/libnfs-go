package implv4

import (
	"github.com/smallfz/libnfs-go/backend"
	"github.com/smallfz/libnfs-go/nfs"
)

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// createSession implements CREATE_SESSION (RFC 5661 §18.36). The first
// CREATE_SESSION call also confirms the client. We advertise a single-slot
// session (MaxRequests=1) to keep the slot table trivial.
func createSession(x nfs.RPCContext, args *nfs.CREATE_SESSION4args) (*nfs.CREATE_SESSION4res, error) {
	bAny := x.Stat().Backend()
	b, ok := bAny.(*backend.Backend)
	if !ok || b == nil {
		return &nfs.CREATE_SESSION4res{Status: nfs.NFS4ERR_SERVERFAULT}, nil
	}
	reg := b.Registry()

	// First CREATE_SESSION confirms the client.
	_ = reg.ConfirmClient(args.ClientId)

	fore := backend.ChannelAttrs{
		HeaderPad:    args.ForeChanAttrs.HeaderPadSize,
		MaxReq:       args.ForeChanAttrs.MaxRequestSize,
		MaxResp:      args.ForeChanAttrs.MaxResponseSize,
		MaxRespCache: args.ForeChanAttrs.MaxResponseSizeCached,
		MaxOps:       args.ForeChanAttrs.MaxOperations,
		MaxReqs:      args.ForeChanAttrs.MaxRequests,
	}
	back := backend.ChannelAttrs{
		HeaderPad:    args.BackChanAttrs.HeaderPadSize,
		MaxReq:       args.BackChanAttrs.MaxRequestSize,
		MaxResp:      args.BackChanAttrs.MaxResponseSize,
		MaxRespCache: args.BackChanAttrs.MaxResponseSizeCached,
		MaxOps:       args.BackChanAttrs.MaxOperations,
		MaxReqs:      args.BackChanAttrs.MaxRequests,
	}

	sess, err := reg.CreateSession(args.ClientId, fore, back)
	if err != nil {
		return &nfs.CREATE_SESSION4res{Status: nfs.NFS4ERR_STALE_CLIENTID}, nil
	}

	resAttrs := nfs.ChannelAttrs4{
		HeaderPadSize:         0,
		MaxRequestSize:        minU32(args.ForeChanAttrs.MaxRequestSize, 1<<20),
		MaxResponseSize:       minU32(args.ForeChanAttrs.MaxResponseSize, 1<<20),
		MaxResponseSizeCached: 0,
		MaxOperations:         minU32(args.ForeChanAttrs.MaxOperations, 64),
		MaxRequests:           1,
	}

	return &nfs.CREATE_SESSION4res{
		Status: nfs.NFS4_OK,
		Ok: &nfs.CREATE_SESSION4resok{
			SessionId:     sess.Id,
			Sequence:      args.Sequence,
			Flags:         0,
			ForeChanAttrs: resAttrs,
			BackChanAttrs: resAttrs,
		},
	}, nil
}
