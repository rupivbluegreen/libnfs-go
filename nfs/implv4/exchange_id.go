package implv4

import (
	"github.com/smallfz/libnfs-go/backend"
	"github.com/smallfz/libnfs-go/nfs"
)

// exchangeId implements EXCHANGE_ID (RFC 5661 §18.35). It registers the client
// owner with the backend SessionRegistry and returns a stable clientid that the
// client uses to call CREATE_SESSION.
func exchangeId(x nfs.RPCContext, args *nfs.EXCHANGE_ID4args) (*nfs.EXCHANGE_ID4res, error) {
	bAny := x.Stat().Backend()
	b, ok := bAny.(*backend.Backend)
	if !ok || b == nil {
		return &nfs.EXCHANGE_ID4res{Status: nfs.NFS4ERR_SERVERFAULT}, nil
	}
	reg := b.Registry()

	var verif [8]byte
	var ownerId []byte
	if args.ClientOwner != nil {
		// ClientOwner4.Verifier is a uint64 in this lib's struct shape.
		v := args.ClientOwner.Verifier
		for i := 0; i < 8; i++ {
			verif[i] = byte(v >> (8 * i))
		}
		ownerId = []byte(args.ClientOwner.OwnerId)
	}

	client, _ := reg.ExchangeId(ownerId, verif)

	return &nfs.EXCHANGE_ID4res{
		Status: nfs.NFS4_OK,
		Ok: &nfs.EXCHANGE_ID4resok{
			ClientId:     client.Id,
			SequenceId:   1,
			Flags:        nfs.EXCHGID4_FLAG_USE_NON_PNFS,
			StateProtect: &nfs.StateProtect4R{How: nfs.SP4_NONE},
			ServerOwner: &nfs.ServerOwner4{
				MinorId: 0,
				MajorId: "s3gw",
			},
			ServerScope:  "s3gw",
			ServerImplId: &nfs.NfsImplId4{Date: &nfs.NfsTime4{}},
		},
	}, nil
}
