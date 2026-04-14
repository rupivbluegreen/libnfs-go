package implv4

import (
	"errors"
	"os"
	"strings"

	"github.com/smallfz/libnfs-go/fs"
	"github.com/smallfz/libnfs-go/log"
	"github.com/smallfz/libnfs-go/nfs"
)

// maxXattrValueSize is the hard cap on a single xattr value. S3 user
// metadata is limited to ~2 KB per key and ~8 KB total across keys; we
// enforce the per-value cap here and leave the cumulative cap to the
// underlying FS, which reports it via os.ErrInvalid / a custom error
// that we map to NFS4ERR_XATTR2BIG.
const maxXattrValueSize = 2048

// xattrFS extracts the optional xattr capability from the current FS,
// or nil if the backend doesn't implement it.
func xattrFS(x nfs.RPCContext) fs.XattrCapable {
	vfs := x.GetFS()
	if vfs == nil {
		return nil
	}
	cap, _ := vfs.(fs.XattrCapable)
	return cap
}

// currentPath resolves the current filehandle to a path. All four
// xattr ops operate on the file identified by the prior PUTFH in the
// compound.
func currentPath(x nfs.RPCContext) (string, uint32) {
	fh := x.Stat().CurrentHandle()
	if fh == nil {
		return "", nfs.NFS4ERR_NOFILEHANDLE
	}
	vfs := x.GetFS()
	if vfs == nil {
		return "", nfs.NFS4ERR_SERVERFAULT
	}
	path, err := vfs.ResolveHandle(fh)
	if err != nil {
		log.Warnf("xattr: ResolveHandle: %v", err)
		return "", nfs.NFS4ERR_STALE
	}
	return path, nfs.NFS4_OK
}

// validateXattrName rejects anything outside the user.* namespace.
// trusted.* / security.* / system.* need a privilege context we don't
// have under AUTH_SYS; mapping them to user-metadata would silently
// bypass the kernel's access checks. We return the specific NFS error
// the caller should report (NOXATTR vs PERM).
func validateXattrName(name string, forWrite bool) uint32 {
	if !strings.HasPrefix(name, "user.") {
		if forWrite {
			return nfs.NFS4ERR_PERM
		}
		return nfs.NFS4ERR_NOXATTR
	}
	return nfs.NFS4_OK
}

// mapXattrError translates FS errors into NFS status codes for xattr
// ops. ErrNotExist → NOXATTR, ErrExist → EXIST, ErrInvalid → INVAL,
// everything else → IO.
func mapXattrError(err error) uint32 {
	if err == nil {
		return nfs.NFS4_OK
	}
	if errors.Is(err, os.ErrNotExist) {
		return nfs.NFS4ERR_NOXATTR
	}
	if errors.Is(err, os.ErrExist) {
		return nfs.NFS4ERR_EXIST
	}
	if errors.Is(err, os.ErrInvalid) {
		return nfs.NFS4ERR_INVAL
	}
	return nfs.NFS4ERR_IO
}

func getXattr(x nfs.RPCContext, args *nfs.GETXATTR4args) (*nfs.GETXATTR4res, error) {
	cap := xattrFS(x)
	if cap == nil {
		return &nfs.GETXATTR4res{Status: nfs.NFS4ERR_NOTSUPP}, nil
	}
	if st := validateXattrName(args.Name, false); st != nfs.NFS4_OK {
		return &nfs.GETXATTR4res{Status: st}, nil
	}
	path, st := currentPath(x)
	if st != nfs.NFS4_OK {
		return &nfs.GETXATTR4res{Status: st}, nil
	}
	val, err := cap.GetXattr(path, args.Name)
	if err != nil {
		return &nfs.GETXATTR4res{Status: mapXattrError(err)}, nil
	}
	return &nfs.GETXATTR4res{
		Status: nfs.NFS4_OK,
		Ok:     &nfs.GETXATTR4resok{Value: val},
	}, nil
}

func setXattr(x nfs.RPCContext, args *nfs.SETXATTR4args) (*nfs.SETXATTR4res, error) {
	cap := xattrFS(x)
	if cap == nil {
		return &nfs.SETXATTR4res{Status: nfs.NFS4ERR_NOTSUPP}, nil
	}
	if st := validateXattrName(args.Name, true); st != nfs.NFS4_OK {
		return &nfs.SETXATTR4res{Status: st}, nil
	}
	if len(args.Value) > maxXattrValueSize {
		return &nfs.SETXATTR4res{Status: nfs.NFS4ERR_XATTR2BIG}, nil
	}
	path, st := currentPath(x)
	if st != nfs.NFS4_OK {
		return &nfs.SETXATTR4res{Status: st}, nil
	}
	if err := cap.SetXattr(path, args.Name, args.Value, args.Option); err != nil {
		return &nfs.SETXATTR4res{Status: mapXattrError(err)}, nil
	}
	return &nfs.SETXATTR4res{
		Status: nfs.NFS4_OK,
		Info:   &nfs.ChangeInfo4{},
	}, nil
}

func listXattrs(x nfs.RPCContext, args *nfs.LISTXATTRS4args) (*nfs.LISTXATTRS4res, error) {
	cap := xattrFS(x)
	if cap == nil {
		return &nfs.LISTXATTRS4res{Status: nfs.NFS4ERR_NOTSUPP}, nil
	}
	path, st := currentPath(x)
	if st != nfs.NFS4_OK {
		return &nfs.LISTXATTRS4res{Status: st}, nil
	}
	names, err := cap.ListXattrs(path)
	if err != nil {
		return &nfs.LISTXATTRS4res{Status: mapXattrError(err)}, nil
	}
	// The backend returns fully-qualified names (e.g. "user.checksum").
	// We only support user.* so this is a no-op filter, but keep the
	// defensive guard in case a backend ever starts returning names
	// from a namespace we don't want to surface.
	filtered := make([]string, 0, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, "user.") {
			filtered = append(filtered, n)
		}
	}
	return &nfs.LISTXATTRS4res{
		Status: nfs.NFS4_OK,
		Ok: &nfs.LISTXATTRS4resok{
			Cookie: args.Cookie, // we don't paginate; echo what we got
			Names:  filtered,
			Eof:    true,
		},
	}, nil
}

func removeXattr(x nfs.RPCContext, args *nfs.REMOVEXATTR4args) (*nfs.REMOVEXATTR4res, error) {
	cap := xattrFS(x)
	if cap == nil {
		return &nfs.REMOVEXATTR4res{Status: nfs.NFS4ERR_NOTSUPP}, nil
	}
	if st := validateXattrName(args.Name, false); st != nfs.NFS4_OK {
		return &nfs.REMOVEXATTR4res{Status: st}, nil
	}
	path, st := currentPath(x)
	if st != nfs.NFS4_OK {
		return &nfs.REMOVEXATTR4res{Status: st}, nil
	}
	if err := cap.RemoveXattr(path, args.Name); err != nil {
		return &nfs.REMOVEXATTR4res{Status: mapXattrError(err)}, nil
	}
	return &nfs.REMOVEXATTR4res{
		Status: nfs.NFS4_OK,
		Info:   &nfs.ChangeInfo4{},
	}, nil
}
