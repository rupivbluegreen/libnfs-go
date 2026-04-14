package implv4

import (
	"github.com/smallfz/libnfs-go/backend"
	"github.com/smallfz/libnfs-go/nfs"
)

// destroySession implements DESTROY_SESSION (RFC 5661 §18.37). Idempotent.
func destroySession(x nfs.RPCContext, args *nfs.DESTROY_SESSION4args) (*nfs.DESTROY_SESSION4res, error) {
	if b, ok := x.Stat().Backend().(*backend.Backend); ok && b != nil {
		_ = b.Registry().DestroySession(args.SessionId)
	}
	return &nfs.DESTROY_SESSION4res{Status: nfs.NFS4_OK}, nil
}
