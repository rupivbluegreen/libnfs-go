package implv4

import (
	"github.com/smallfz/libnfs-go/fs"
	"github.com/smallfz/libnfs-go/nfs"
)

// lookupOpenFile resolves a stateid to the OpenedFile registered with
// the per-connection state during OPEN. v4.0 clients send back the
// server-assigned SeqId unchanged; v4.1+ clients increment SeqId per
// operation but preserve Other[0], which OPEN4res stashes as the
// stable identifier. Both lookups are tried so the same handler code
// works for 4.0, 4.1, and 4.2.
func lookupOpenFile(x nfs.RPCContext, sid *nfs.StateId4) fs.FileOpenState {
	if sid == nil {
		return nil
	}
	if of := x.Stat().GetOpenedFile(sid.SeqId); of != nil {
		return of
	}
	if sid.Other[0] != 0 {
		if of := x.Stat().GetOpenedFile(sid.Other[0]); of != nil {
			return of
		}
	}
	return nil
}
