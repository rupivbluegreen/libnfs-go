package implv4

import (
	"github.com/smallfz/libnfs-go/nfs"
)

// freeStateId implements FREE_STATEID (RFC 5661 §18.38). The S3 backend has no
// long-lived stateids to release, so this is always a successful no-op.
func freeStateId(x nfs.RPCContext, args *nfs.FREE_STATEID4args) (*nfs.FREE_STATEID4res, error) {
	_ = x
	_ = args
	return &nfs.FREE_STATEID4res{Status: nfs.NFS4_OK}, nil
}
