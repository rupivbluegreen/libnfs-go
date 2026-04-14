package implv4

import (
	"github.com/smallfz/libnfs-go/fs"
	"github.com/smallfz/libnfs-go/log"
	"github.com/smallfz/libnfs-go/nfs"
)

// copyOp implements NFSv4.2 COPY (RFC 7862 §15.2) for the common case
// issued by `cp a b` on Linux: a synchronous, intra-server, full-object
// copy with src_offset=dst_offset=0 and count=0 or count=src_size.
//
// Partial-range copies and async/notify variants return NFS4ERR_NOTSUPP,
// which the Linux kernel handles by falling back to client-side
// READ+WRITE emulation automatically. This keeps the handler simple
// and turns the one case that actually matters for an S3-backed FS —
// a full-object server-side copy — into a single S3 CopyObject request
// via the fs.CopyCapable optional interface.
func copyOp(x nfs.RPCContext, args *nfs.COPY4args) (*nfs.COPY4res, error) {
	src := lookupOpenFile(x, &args.SrcStateId)
	dst := lookupOpenFile(x, &args.DstStateId)
	if src == nil || dst == nil {
		log.Warnf("copy: missing src or dst open state (src=%v dst=%v)", src != nil, dst != nil)
		return &nfs.COPY4res{Status: nfs.NFS4ERR_BAD_STATEID}, nil
	}

	if !args.Synchronous {
		// We don't implement async offload / wrCallback.
		return &nfs.COPY4res{Status: nfs.NFS4ERR_NOTSUPP}, nil
	}
	if args.SrcOffset != 0 || args.DstOffset != 0 {
		// Only full-object copies hit the S3 CopyObject fast path.
		return &nfs.COPY4res{Status: nfs.NFS4ERR_NOTSUPP}, nil
	}

	srcInfo, err := src.File().Stat()
	if err != nil {
		log.Warnf("copy: src stat: %v", err)
		return &nfs.COPY4res{Status: nfs.NFS4ERR_IO}, nil
	}
	srcSize := uint64(srcInfo.Size())
	if args.Count != 0 && args.Count != srcSize {
		return &nfs.COPY4res{Status: nfs.NFS4ERR_NOTSUPP}, nil
	}

	cap, ok := x.GetFS().(fs.CopyCapable)
	if !ok {
		return &nfs.COPY4res{Status: nfs.NFS4ERR_NOTSUPP}, nil
	}
	if err := cap.Copy(src.Path(), dst.Path()); err != nil {
		log.Warnf("copy: %s → %s: %v", src.Path(), dst.Path(), err)
		return &nfs.COPY4res{Status: nfs.NFS4ERR_SERVERFAULT}, nil
	}

	return &nfs.COPY4res{
		Status: nfs.NFS4_OK,
		Ok: &nfs.COPY4resok{
			Response: nfs.WriteResponse4{
				Count:     srcSize,
				Committed: nfs.FILE_SYNC4,
			},
			Consecutive: true,
			Synchronous: true,
		},
	}, nil
}
