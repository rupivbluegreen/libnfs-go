package implv4

import (
	"github.com/smallfz/libnfs-go/nfs"
)

// reclaimComplete implements RECLAIM_COMPLETE (RFC 5661 §18.51). Stateless S3
// backend has nothing to reclaim.
func reclaimComplete(x nfs.RPCContext, args *nfs.RECLAIM_COMPLETE4args) (*nfs.RECLAIM_COMPLETE4res, error) {
	_ = x
	_ = args
	return &nfs.RECLAIM_COMPLETE4res{Status: nfs.NFS4_OK}, nil
}
