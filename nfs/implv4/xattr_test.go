package implv4

import (
	"os"
	"testing"

	"github.com/smallfz/libnfs-go/fs"
	"github.com/smallfz/libnfs-go/nfs"
	"github.com/smallfz/libnfs-go/xdr"
)

// --- fake FS that implements only the xattr capability ---

type xattrFakeFS struct {
	store map[string][]byte
	// overrideErrs lets tests force specific error returns
	getErr    error
	setErr    error
	listErr   error
	removeErr error
}

func newXattrFS() *xattrFakeFS { return &xattrFakeFS{store: map[string][]byte{}} }

// fs.FS stubs — the xattr handlers never call any of these except
// ResolveHandle (via currentPath). Keep them minimal.

func (f *xattrFakeFS) SetCreds(fs.Creds)                       {}
func (f *xattrFakeFS) Open(string) (fs.File, error)            { return nil, os.ErrNotExist }
func (f *xattrFakeFS) OpenFile(string, int, os.FileMode) (fs.File, error) {
	return nil, os.ErrNotExist
}
func (f *xattrFakeFS) Stat(string) (fs.FileInfo, error)   { return nil, os.ErrNotExist }
func (f *xattrFakeFS) Chmod(string, os.FileMode) error    { return nil }
func (f *xattrFakeFS) Chown(string, int, int) error       { return nil }
func (f *xattrFakeFS) Symlink(string, string) error       { return nil }
func (f *xattrFakeFS) Readlink(string) (string, error)    { return "", nil }
func (f *xattrFakeFS) Link(string, string) error          { return nil }
func (f *xattrFakeFS) Rename(string, string) error        { return nil }
func (f *xattrFakeFS) Remove(string) error                { return nil }
func (f *xattrFakeFS) MkdirAll(string, os.FileMode) error { return nil }
func (f *xattrFakeFS) GetFileId(fs.FileInfo) uint64       { return 0 }
func (f *xattrFakeFS) GetRootHandle() []byte              { return []byte{1} }
func (f *xattrFakeFS) GetHandle(fs.FileInfo) ([]byte, error) {
	return []byte{1}, nil
}
func (f *xattrFakeFS) ResolveHandle([]byte) (string, error) { return "/file", nil }
func (f *xattrFakeFS) Attributes() *fs.Attributes           { return &fs.Attributes{} }

// XattrCapable impl

func (f *xattrFakeFS) GetXattr(path, name string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.store[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return v, nil
}

func (f *xattrFakeFS) SetXattr(path, name string, value []byte, option uint32) error {
	if f.setErr != nil {
		return f.setErr
	}
	_, exists := f.store[name]
	switch option {
	case nfs.SETXATTR4_CREATE:
		if exists {
			return os.ErrExist
		}
	case nfs.SETXATTR4_REPLACE:
		if !exists {
			return os.ErrNotExist
		}
	}
	f.store[name] = append([]byte(nil), value...)
	return nil
}

func (f *xattrFakeFS) ListXattrs(path string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]string, 0, len(f.store))
	for k := range f.store {
		out = append(out, k)
	}
	return out, nil
}

func (f *xattrFakeFS) RemoveXattr(path, name string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	if _, ok := f.store[name]; !ok {
		return os.ErrNotExist
	}
	delete(f.store, name)
	return nil
}

// --- fake stat + ctx that return a current FH and the fake FS ---

type xattrFakeStat struct{}

func (xattrFakeStat) SetCurrentHandle(nfs.FileHandle4)          {}
func (xattrFakeStat) CurrentHandle() nfs.FileHandle4            { return []byte{1, 2, 3} }
func (xattrFakeStat) PushHandle(nfs.FileHandle4)                {}
func (xattrFakeStat) PeekHandle() (nfs.FileHandle4, bool)       { return nil, false }
func (xattrFakeStat) PopHandle() (nfs.FileHandle4, bool)        { return nil, false }
func (xattrFakeStat) SetClientId(uint64)                        {}
func (xattrFakeStat) ClientId() (uint64, bool)                  { return 0, false }
func (xattrFakeStat) AddOpenedFile(string, fs.File) uint32      { return 0 }
func (xattrFakeStat) GetOpenedFile(uint32) fs.FileOpenState     { return nil }
func (xattrFakeStat) FindOpenedFiles(string) []fs.FileOpenState { return nil }
func (xattrFakeStat) RemoveOpenedFile(uint32) fs.FileOpenState  { return nil }
func (xattrFakeStat) CloseAndRemoveStallFiles()                 {}
func (xattrFakeStat) CleanUp()                                  {}
func (xattrFakeStat) Backend() interface{}                      { return nil }
func (xattrFakeStat) CurrentSession() interface{}               { return nil }
func (xattrFakeStat) SetCurrentSession(interface{})             {}
func (xattrFakeStat) PendingSequenceResponse() interface{}      { return nil }
func (xattrFakeStat) SetPendingSequenceResponse(interface{})    {}

type xattrFakeCtx struct {
	stat nfs.StatService
	vfs  fs.FS
}

func (c *xattrFakeCtx) Reader() *xdr.Reader                                 { return nil }
func (c *xattrFakeCtx) Writer() *xdr.Writer                                 { return nil }
func (c *xattrFakeCtx) Authenticate(*nfs.Auth, *nfs.Auth) (*nfs.Auth, error) { return nil, nil }
func (c *xattrFakeCtx) GetFS() fs.FS                                        { return c.vfs }
func (c *xattrFakeCtx) Stat() nfs.StatService                               { return c.stat }

func newXattrCtx(f *xattrFakeFS) *xattrFakeCtx {
	return &xattrFakeCtx{stat: xattrFakeStat{}, vfs: f}
}

// --- tests ---

func TestXattr_RoundTrip(t *testing.T) {
	f := newXattrFS()
	ctx := newXattrCtx(f)

	sres, _ := setXattr(ctx, &nfs.SETXATTR4args{
		Option: nfs.SETXATTR4_EITHER,
		Name:   "checksum",
		Value:  []byte("deadbeef"),
	})
	if sres.Status != nfs.NFS4_OK {
		t.Fatalf("setXattr: status=%d", sres.Status)
	}

	gres, _ := getXattr(ctx, &nfs.GETXATTR4args{Name: "checksum"})
	if gres.Status != nfs.NFS4_OK {
		t.Fatalf("getXattr: status=%d", gres.Status)
	}
	if string(gres.Ok.Value) != "deadbeef" {
		t.Fatalf("unexpected value: %q", gres.Ok.Value)
	}

	lres, _ := listXattrs(ctx, &nfs.LISTXATTRS4args{})
	if lres.Status != nfs.NFS4_OK {
		t.Fatalf("listXattrs: status=%d", lres.Status)
	}
	if len(lres.Ok.Names) != 1 || lres.Ok.Names[0] != "checksum" {
		t.Fatalf("unexpected list: %v", lres.Ok.Names)
	}

	rres, _ := removeXattr(ctx, &nfs.REMOVEXATTR4args{Name: "checksum"})
	if rres.Status != nfs.NFS4_OK {
		t.Fatalf("removeXattr: status=%d", rres.Status)
	}

	gres2, _ := getXattr(ctx, &nfs.GETXATTR4args{Name: "checksum"})
	if gres2.Status != nfs.NFS4ERR_NOXATTR {
		t.Fatalf("expected NOXATTR after remove, got %d", gres2.Status)
	}
}

func TestXattr_NamespacePrefixRejected(t *testing.T) {
	ctx := newXattrCtx(newXattrFS())
	// Wire names must be naked — any dotted namespace prefix is a
	// protocol violation and returns INVAL.
	for _, name := range []string{"user.foo", "trusted.bar", "security.selinux", "system.x"} {
		s, _ := setXattr(ctx, &nfs.SETXATTR4args{Name: name, Value: []byte("x")})
		if s.Status != nfs.NFS4ERR_INVAL {
			t.Fatalf("SET %q: expected INVAL, got %d", name, s.Status)
		}
		g, _ := getXattr(ctx, &nfs.GETXATTR4args{Name: name})
		if g.Status != nfs.NFS4ERR_INVAL {
			t.Fatalf("GET %q: expected INVAL, got %d", name, g.Status)
		}
	}
}

func TestXattr_CreateExistingFails(t *testing.T) {
	f := newXattrFS()
	ctx := newXattrCtx(f)
	setXattr(ctx, &nfs.SETXATTR4args{Option: nfs.SETXATTR4_EITHER, Name: "x", Value: []byte("a")})

	r, _ := setXattr(ctx, &nfs.SETXATTR4args{
		Option: nfs.SETXATTR4_CREATE,
		Name:   "x",
		Value:  []byte("b"),
	})
	if r.Status != nfs.NFS4ERR_EXIST {
		t.Fatalf("expected EXIST, got %d", r.Status)
	}
}

func TestXattr_ReplaceMissingFails(t *testing.T) {
	ctx := newXattrCtx(newXattrFS())
	r, _ := setXattr(ctx, &nfs.SETXATTR4args{
		Option: nfs.SETXATTR4_REPLACE,
		Name:   "nope",
		Value:  []byte("b"),
	})
	if r.Status != nfs.NFS4ERR_NOXATTR {
		t.Fatalf("expected NOXATTR, got %d", r.Status)
	}
}

func TestXattr_ValueTooBig(t *testing.T) {
	ctx := newXattrCtx(newXattrFS())
	big := make([]byte, maxXattrValueSize+1)
	r, _ := setXattr(ctx, &nfs.SETXATTR4args{
		Option: nfs.SETXATTR4_EITHER,
		Name:   "big",
		Value:  big,
	})
	if r.Status != nfs.NFS4ERR_XATTR2BIG {
		t.Fatalf("expected XATTR2BIG, got %d", r.Status)
	}
}

func TestXattr_BackendAbsentReturnsNotsupp(t *testing.T) {
	// ctx with vfs=nil → no xattr capability.
	ctx := &xattrFakeCtx{stat: xattrFakeStat{}, vfs: nil}
	g, _ := getXattr(ctx, &nfs.GETXATTR4args{Name: "x"})
	if g.Status != nfs.NFS4ERR_NOTSUPP {
		t.Fatalf("expected NOTSUPP, got %d", g.Status)
	}
}
