package implv4

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/smallfz/libnfs-go/fs"
	"github.com/smallfz/libnfs-go/nfs"
	"github.com/smallfz/libnfs-go/xdr"
)

// --- fake fs.File plumbing for SEEK tests ---

type seekFakeInfo struct{ size int64 }

func (seekFakeInfo) Name() string       { return "x" }
func (i seekFakeInfo) Size() int64      { return i.size }
func (seekFakeInfo) Mode() os.FileMode  { return 0644 }
func (seekFakeInfo) ModTime() time.Time { return time.Time{} }
func (seekFakeInfo) IsDir() bool        { return false }
func (seekFakeInfo) Sys() interface{}   { return nil }
func (seekFakeInfo) ATime() time.Time   { return time.Time{} }
func (seekFakeInfo) CTime() time.Time   { return time.Time{} }
func (seekFakeInfo) NumLinks() int      { return 1 }

type seekFakeFile struct{ size int64 }

func (f *seekFakeFile) Name() string                             { return "x" }
func (f *seekFakeFile) Stat() (fs.FileInfo, error)               { return seekFakeInfo{size: f.size}, nil }
func (f *seekFakeFile) Read(p []byte) (int, error)               { return 0, io.EOF }
func (f *seekFakeFile) Write(p []byte) (int, error)              { return len(p), nil }
func (f *seekFakeFile) Close() error                             { return nil }
func (f *seekFakeFile) Seek(off int64, whence int) (int64, error) { return off, nil }
func (f *seekFakeFile) Truncate() error                          { return nil }
func (f *seekFakeFile) Sync() error                              { return nil }
func (f *seekFakeFile) Readdir(int) ([]fs.FileInfo, error)       { return nil, nil }

type seekFakeOpenState struct {
	f fs.File
}

func (s *seekFakeOpenState) File() fs.File { return s.f }
func (s *seekFakeOpenState) Path() string  { return "/x" }

// seekFakeStat is a fresh StatService that returns a caller-provided
// FileOpenState from GetOpenedFile. It intentionally does not embed
// fakeStat (from session_ops_test.go) so the override is local and
// obvious.
type seekFakeStat struct{ state fs.FileOpenState }

func (seekFakeStat) SetCurrentHandle(nfs.FileHandle4)              {}
func (seekFakeStat) CurrentHandle() nfs.FileHandle4                { return nil }
func (seekFakeStat) PushHandle(nfs.FileHandle4)                    {}
func (seekFakeStat) PeekHandle() (nfs.FileHandle4, bool)           { return nil, false }
func (seekFakeStat) PopHandle() (nfs.FileHandle4, bool)            { return nil, false }
func (seekFakeStat) SetClientId(uint64)                            {}
func (seekFakeStat) ClientId() (uint64, bool)                      { return 0, false }
func (seekFakeStat) AddOpenedFile(string, fs.File) uint32          { return 0 }
func (s seekFakeStat) GetOpenedFile(uint32) fs.FileOpenState       { return s.state }
func (seekFakeStat) FindOpenedFiles(string) []fs.FileOpenState     { return nil }
func (seekFakeStat) RemoveOpenedFile(uint32) fs.FileOpenState      { return nil }
func (seekFakeStat) CloseAndRemoveStallFiles()                     {}
func (seekFakeStat) CleanUp()                                      {}
func (seekFakeStat) Backend() interface{}                          { return nil }
func (seekFakeStat) CurrentSession() interface{}                   { return nil }
func (seekFakeStat) SetCurrentSession(interface{})                 {}
func (seekFakeStat) PendingSequenceResponse() interface{}          { return nil }
func (seekFakeStat) SetPendingSequenceResponse(interface{})        {}

type seekFakeCtx struct{ stat nfs.StatService }

func (c *seekFakeCtx) Reader() *xdr.Reader                               { return nil }
func (c *seekFakeCtx) Writer() *xdr.Writer                               { return nil }
func (c *seekFakeCtx) Authenticate(*nfs.Auth, *nfs.Auth) (*nfs.Auth, error) { return nil, nil }
func (c *seekFakeCtx) GetFS() fs.FS                                      { return nil }
func (c *seekFakeCtx) Stat() nfs.StatService                             { return c.stat }

func newSeekCtx(fileSize int64) nfs.RPCContext {
	return &seekFakeCtx{stat: seekFakeStat{
		state: &seekFakeOpenState{f: &seekFakeFile{size: fileSize}},
	}}
}

// --- tests ---

func TestSeek_DataBeforeEof(t *testing.T) {
	ctx := newSeekCtx(4096)
	res, err := seek(ctx, &nfs.SEEK4args{
		StateId: nfs.StateId4{SeqId: 1},
		Offset:  1024,
		What:    nfs.NFS4_CONTENT_DATA,
	})
	if err != nil || res.Status != nfs.NFS4_OK {
		t.Fatalf("seek(data,1024): status=%d err=%v", res.Status, err)
	}
	if res.Ok.Eof {
		t.Fatalf("expected eof=false, got true")
	}
	if res.Ok.Offset != 1024 {
		t.Fatalf("expected offset=1024, got %d", res.Ok.Offset)
	}
}

func TestSeek_DataAtEofIsNxio(t *testing.T) {
	ctx := newSeekCtx(4096)
	res, _ := seek(ctx, &nfs.SEEK4args{
		StateId: nfs.StateId4{SeqId: 1},
		Offset:  4096,
		What:    nfs.NFS4_CONTENT_DATA,
	})
	if res.Status != nfs.NFS4ERR_NXIO {
		t.Fatalf("expected NFS4ERR_NXIO for SEEK_DATA at EOF, got %d", res.Status)
	}
}

func TestSeek_HoleReturnsEof(t *testing.T) {
	ctx := newSeekCtx(8192)
	res, _ := seek(ctx, &nfs.SEEK4args{
		StateId: nfs.StateId4{SeqId: 1},
		Offset:  0,
		What:    nfs.NFS4_CONTENT_HOLE,
	})
	if res.Status != nfs.NFS4_OK {
		t.Fatalf("SEEK_HOLE: status=%d", res.Status)
	}
	if !res.Ok.Eof {
		t.Fatalf("expected eof=true")
	}
	if res.Ok.Offset != 8192 {
		t.Fatalf("expected offset=8192, got %d", res.Ok.Offset)
	}
}

func TestSeek_InvalidWhat(t *testing.T) {
	ctx := newSeekCtx(1024)
	res, _ := seek(ctx, &nfs.SEEK4args{
		StateId: nfs.StateId4{SeqId: 1},
		What:    999,
	})
	if res.Status != nfs.NFS4ERR_INVAL {
		t.Fatalf("expected INVAL, got %d", res.Status)
	}
}

func TestSeek_MissingStateid(t *testing.T) {
	ctx := &seekFakeCtx{stat: seekFakeStat{state: nil}}
	res, _ := seek(ctx, &nfs.SEEK4args{
		StateId: nfs.StateId4{SeqId: 0},
		What:    nfs.NFS4_CONTENT_DATA,
	})
	if res.Status != nfs.NFS4ERR_BAD_STATEID {
		t.Fatalf("expected BAD_STATEID, got %d", res.Status)
	}
}
