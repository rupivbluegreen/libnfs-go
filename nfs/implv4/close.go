package implv4

import (
	"github.com/smallfz/libnfs-go/log"
	"github.com/smallfz/libnfs-go/nfs"
)

func closeFile(x nfs.RPCContext, args *nfs.CLOSE4args) (*nfs.CLOSE4res, error) {
	seqId := uint32(0)
	var other [3]uint32
	if args != nil && args.OpenStateId != nil {
		seqId = args.OpenStateId.SeqId
		other = args.OpenStateId.Other
	}

	log.Infof("CLOSE4, seq=%d other=%v", seqId, other)

	f := x.Stat().RemoveOpenedFile(seqId)
	if f == nil && other[0] != 0 {
		f = x.Stat().RemoveOpenedFile(other[0])
	}
	if f == nil {
		log.Warnf("close: opened file in stat not exists.")
		return &nfs.CLOSE4res{Status: nfs.NFS4ERR_INVAL}, nil
	} else {
		log.Debugf(" - %s closed.", f.File().Name())
		f.File().Close()
	}

	res := &nfs.CLOSE4res{
		Status: nfs.NFS4_OK,
		Ok:     args.OpenStateId,
	}
	return res, nil
}
