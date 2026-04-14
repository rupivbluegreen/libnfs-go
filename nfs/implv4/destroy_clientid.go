package implv4

import (
	"github.com/smallfz/libnfs-go/backend"
	"github.com/smallfz/libnfs-go/nfs"
)

// destroyClientId implements DESTROY_CLIENTID (RFC 5661 §18.50). Idempotent.
func destroyClientId(x nfs.RPCContext, args *nfs.DESTROY_CLIENTID4args) (*nfs.DESTROY_CLIENTID4res, error) {
	if b, ok := x.Stat().Backend().(*backend.Backend); ok && b != nil {
		_ = b.Registry().DestroyClient(args.ClientId)
	}
	return &nfs.DESTROY_CLIENTID4res{Status: nfs.NFS4_OK}, nil
}
