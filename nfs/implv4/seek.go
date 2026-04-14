package implv4

import (
	"github.com/smallfz/libnfs-go/log"
	"github.com/smallfz/libnfs-go/nfs"
)

// seek implements NFSv4.2 SEEK (RFC 7862 §15.11) as a "no-holes"
// filesystem. S3-backed objects are never sparse, so SEEK_DATA with an
// offset inside the file returns that same offset, SEEK_DATA past EOF
// returns NFS4ERR_NXIO, and SEEK_HOLE always returns the EOF offset
// with eof=true. This is correct for a flat object store and keeps
// tools like `xfs_io -c "seek"` and `lseek(SEEK_HOLE)` from aborting.
func seek(x nfs.RPCContext, args *nfs.SEEK4args) (*nfs.SEEK4res, error) {
	of := lookupOpenFile(x, &args.StateId)
	if of == nil {
		log.Warnf("seek: no open file for stateid seq=%d other=%v",
			args.StateId.SeqId, args.StateId.Other)
		return &nfs.SEEK4res{Status: nfs.NFS4ERR_BAD_STATEID}, nil
	}
	fi, err := of.File().Stat()
	if err != nil {
		log.Warnf("seek: stat: %v", err)
		return &nfs.SEEK4res{Status: nfs.NFS4ERR_IO}, nil
	}
	size := uint64(fi.Size())
	switch args.What {
	case nfs.NFS4_CONTENT_DATA:
		if args.Offset >= size {
			return &nfs.SEEK4res{Status: nfs.NFS4ERR_NXIO}, nil
		}
		return &nfs.SEEK4res{
			Status: nfs.NFS4_OK,
			Ok:     &nfs.SEEK4resok{Eof: false, Offset: args.Offset},
		}, nil
	case nfs.NFS4_CONTENT_HOLE:
		return &nfs.SEEK4res{
			Status: nfs.NFS4_OK,
			Ok:     &nfs.SEEK4resok{Eof: true, Offset: size},
		}, nil
	}
	return &nfs.SEEK4res{Status: nfs.NFS4ERR_INVAL}, nil
}
