package nfs

import (
	"fmt"
	"io"
	"io/fs"
	"os"
)

const (
	NFS4_OK        = uint32(0)  /* everything is okay       */
	NFS4ERR_PERM   = uint32(1)  /* caller not privileged    */
	NFS4ERR_NOENT  = uint32(2)  /* no such file/directory   */
	NFS4ERR_IO     = uint32(5)  /* hard I/O error           */
	NFS4ERR_NXIO   = uint32(6)  /* no such device           */
	NFS4ERR_ACCESS = uint32(13) /* access denied            */
	NFS4ERR_EXIST  = uint32(17) /* file already exists      */
	NFS4ERR_XDEV   = uint32(18) /* different file systems   */
	/* Unused/reserved        19 */
	NFS4ERR_NOTDIR              = uint32(20)    /* should be a directory    */
	NFS4ERR_ISDIR               = uint32(21)    /* should not be directory  */
	NFS4ERR_INVAL               = uint32(22)    /* invalid argument         */
	NFS4ERR_FBIG                = uint32(27)    /* file exceeds server max  */
	NFS4ERR_NOSPC               = uint32(28)    /* no space on file system  */
	NFS4ERR_ROFS                = uint32(30)    /* read-only file system    */
	NFS4ERR_MLINK               = uint32(31)    /* too many hard links      */
	NFS4ERR_NAMETOOLONG         = uint32(63)    /* name exceeds server max  */
	NFS4ERR_NOTEMPTY            = uint32(66)    /* directory not empty      */
	NFS4ERR_DQUOT               = uint32(69)    /* hard quota limit reached */
	NFS4ERR_STALE               = uint32(70)    /* file no longer exists    */
	NFS4ERR_BADHANDLE           = uint32(10001) /* Illegal filehandle       */
	NFS4ERR_BAD_COOKIE          = uint32(10003) /* READDIR cookie is stale  */
	NFS4ERR_NOTSUPP             = uint32(10004) /* operation not supported  */
	NFS4ERR_TOOSMALL            = uint32(10005) /* response limit exceeded  */
	NFS4ERR_SERVERFAULT         = uint32(10006) /* undefined server error   */
	NFS4ERR_BADTYPE             = uint32(10007) /* type invalid for CREATE  */
	NFS4ERR_DELAY               = uint32(10008) /* file "busy" - retry      */
	NFS4ERR_SAME                = uint32(10009) /* nverify says attrs same  */
	NFS4ERR_DENIED              = uint32(10010) /* lock unavailable         */
	NFS4ERR_EXPIRED             = uint32(10011) /* lock lease expired       */
	NFS4ERR_LOCKED              = uint32(10012) /* I/O failed due to lock   */
	NFS4ERR_GRACE               = uint32(10013) /* in grace period          */
	NFS4ERR_FHEXPIRED           = uint32(10014) /* filehandle expired       */
	NFS4ERR_SHARE_DENIED        = uint32(10015) /* share reserve denied     */
	NFS4ERR_WRONGSEC            = uint32(10016) /* wrong security flavor    */
	NFS4ERR_CLID_INUSE          = uint32(10017) /* clientid in use          */
	NFS4ERR_RESOURCE            = uint32(10018) /* resource exhaustion      */
	NFS4ERR_MOVED               = uint32(10019) /* file system relocated    */
	NFS4ERR_NOFILEHANDLE        = uint32(10020) /* current FH is not set    */
	NFS4ERR_MINOR_VERS_MISMATCH = uint32(10021) /* minor vers not supp */
	NFS4ERR_STALE_CLIENTID      = uint32(10022) /* server has rebooted      */
	NFS4ERR_STALE_STATEID       = uint32(10023) /* server has rebooted      */
	NFS4ERR_OLD_STATEID         = uint32(10024) /* state is out of sync     */
	NFS4ERR_BAD_STATEID         = uint32(10025) /* incorrect stateid        */
	NFS4ERR_BAD_SEQID           = uint32(10026) /* request is out of seq.   */
	NFS4ERR_NOT_SAME            = uint32(10027) /* verify - attrs not same  */
	NFS4ERR_LOCK_RANGE          = uint32(10028) /* lock range not supported */
	NFS4ERR_SYMLINK             = uint32(10029) /* should be file/directory */
	NFS4ERR_RESTOREFH           = uint32(10030) /* no saved filehandle      */
	NFS4ERR_LEASE_MOVED         = uint32(10031) /* some file system moved   */
	NFS4ERR_ATTRNOTSUPP         = uint32(10032) /* recommended attr not sup */
	NFS4ERR_NO_GRACE            = uint32(10033) /* reclaim outside of grace */
	NFS4ERR_RECLAIM_BAD         = uint32(10034) /* reclaim error at server  */
	NFS4ERR_RECLAIM_CONFLICT    = uint32(10035) /* conflict on reclaim    */
	NFS4ERR_BADXDR              = uint32(10036) /* XDR decode failed        */
	NFS4ERR_LOCKS_HELD          = uint32(10037) /* file locks held at CLOSE */
	NFS4ERR_OPENMODE            = uint32(10038) /* conflict in OPEN and I/O */
	NFS4ERR_BADOWNER            = uint32(10039) /* owner translation bad    */
	NFS4ERR_BADCHAR             = uint32(10040) /* UTF-8 char not supported */
	NFS4ERR_BADNAME             = uint32(10041) /* name not supported       */
	NFS4ERR_BAD_RANGE           = uint32(10042) /* lock range not supported */
	NFS4ERR_LOCK_NOTSUPP        = uint32(10043) /* no atomic up/downgrade   */
	NFS4ERR_OP_ILLEGAL          = uint32(10044) /* undefined operation      */
	NFS4ERR_DEADLOCK            = uint32(10045) /* file locking deadlock    */
	NFS4ERR_FILE_OPEN           = uint32(10046) /* open file blocks op.     */
	NFS4ERR_ADMIN_REVOKED       = uint32(10047) /* lock-owner state revoked */
	NFS4ERR_CB_PATH_DOWN        = uint32(10048) /* callback path down       */
	NFS4ERR_BADSESSION          = uint32(10052) /* unknown sessionid        */
	NFS4ERR_BADSLOT             = uint32(10053) /* slot id out of range     */
	NFS4ERR_SEQ_MISORDERED      = uint32(10063) /* sequence id out of order */
	NFS4ERR_OP_NOT_IN_SESSION   = uint32(10071) /* op needs SEQUENCE first  */
	NFS4ERR_SEQUENCE_POS        = uint32(10080) /* SEQUENCE not first op    */

	// rfc8276 xattrs
	NFS4ERR_NOXATTR   = uint32(10095) /* xattr does not exist     */
	NFS4ERR_XATTR2BIG = uint32(10096) /* xattr value too large    */
)

func NFS4err(err error) uint32 {
	switch err {
	case nil:
		return NFS4_OK
	case fs.ErrPermission:
		return NFS4ERR_PERM
	case fs.ErrNotExist:
		return NFS4ERR_NOENT
	case fs.ErrExist:
		return NFS4ERR_EXIST
	case fs.ErrClosed:
		return NFS4ERR_IO
	}

	// Handle syscall errors

	if os.IsNotExist(err) {
		return NFS4ERR_NOENT
	}

	if os.IsExist(err) {
		return NFS4ERR_EXIST
	}

	if os.IsPermission(err) {
		return NFS4ERR_PERM
	}

	// os.LinkError
	return NFS4ERR_PERM
}

const (
	PROC4_VOID     = uint32(0)
	PROC4_COMPOUND = uint32(1)
)

const (
	OP4_ACCESS              = uint32(3)
	OP4_CLOSE               = uint32(4)
	OP4_COMMIT              = uint32(5)
	OP4_CREATE              = uint32(6)
	OP4_DELEGPURGE          = uint32(7)
	OP4_DELEGRETURN         = uint32(8)
	OP4_GETATTR             = uint32(9)
	OP4_GETFH               = uint32(10)
	OP4_LINK                = uint32(11)
	OP4_LOCK                = uint32(12)
	OP4_LOCKT               = uint32(13)
	OP4_LOCKU               = uint32(14)
	OP4_LOOKUP              = uint32(15)
	OP4_LOOKUPP             = uint32(16)
	OP4_NVERIFY             = uint32(17)
	OP4_OPEN                = uint32(18)
	OP4_OPENATTR            = uint32(19)
	OP4_OPEN_CONFIRM        = uint32(20)
	OP4_OPEN_DOWNGRADE      = uint32(21)
	OP4_PUTFH               = uint32(22)
	OP4_PUTPUBFH            = uint32(23)
	OP4_PUTROOTFH           = uint32(24)
	OP4_READ                = uint32(25)
	OP4_READDIR             = uint32(26)
	OP4_READLINK            = uint32(27)
	OP4_REMOVE              = uint32(28)
	OP4_RENAME              = uint32(29)
	OP4_RENEW               = uint32(30)
	OP4_RESTOREFH           = uint32(31)
	OP4_SAVEFH              = uint32(32)
	OP4_SECINFO             = uint32(33)
	OP4_SETATTR             = uint32(34)
	OP4_SETCLIENTID         = uint32(35)
	OP4_SETCLIENTID_CONFIRM = uint32(36)
	OP4_VERIFY              = uint32(37)
	OP4_WRITE               = uint32(38)
	OP4_RELEASE_LOCKOWNER   = uint32(39)
	OP4_EXCHANGE_ID         = uint32(42) // nfs-v4.1, rfc5661
	OP4_CREATE_SESSION      = uint32(43) // nfs-v4.1, rfc5661
	OP4_DESTROY_SESSION     = uint32(44) // nfs-v4.1, rfc5661
	OP4_FREE_STATEID        = uint32(45) // nfs-v4.1, rfc5661
	OP4_SECINFO_NO_NAME     = uint32(52) // nfs-v4.1, rfc5661
	OP4_SEQUENCE            = uint32(53) // nfs-v4.1, rfc5661
	OP4_DESTROY_CLIENTID    = uint32(57) // nfs-v4.1, rfc5661
	OP4_RECLAIM_COMPLETE    = uint32(58) // nfs-v4.1, rfc5661

	// nfs-v4.2, rfc7862
	OP4_ALLOCATE       = uint32(59)
	OP4_COPY           = uint32(60)
	OP4_COPY_NOTIFY    = uint32(61)
	OP4_DEALLOCATE     = uint32(62)
	OP4_IO_ADVISE      = uint32(63)
	OP4_LAYOUTERROR    = uint32(64)
	OP4_LAYOUTSTATS    = uint32(65)
	OP4_OFFLOAD_CANCEL = uint32(66)
	OP4_OFFLOAD_STATUS = uint32(67)
	OP4_READ_PLUS      = uint32(68)
	OP4_SEEK           = uint32(69)
	OP4_WRITE_SAME     = uint32(70)
	OP4_CLONE          = uint32(71)

	// rfc8276 xattrs (also v4.2)
	OP4_GETXATTR    = uint32(72)
	OP4_SETXATTR    = uint32(73)
	OP4_LISTXATTRS  = uint32(74)
	OP4_REMOVEXATTR = uint32(75)

	OP4_ILLEGAL = uint32(10044)
)

// SEEK4args.What (RFC 7862 §15.11)
const (
	NFS4_CONTENT_DATA = uint32(0)
	NFS4_CONTENT_HOLE = uint32(1)
)

// SETXATTR4args.Option (RFC 8276)
const (
	SETXATTR4_EITHER  = uint32(0)
	SETXATTR4_CREATE  = uint32(1)
	SETXATTR4_REPLACE = uint32(2)
)

const (
	PROC4_CB_NULL     = uint32(0)
	PROC4_CB_COMPOUND = uint32(1)
)

const (
	OP4_CB_GETATTR = uint32(3)
	OP4_CB_RECALL  = uint32(4)
	OP4_CB_ILLEGAL = uint32(10044)
)

func Proc4Name(proc uint32) string {
	switch proc {
	case PROC4_VOID:
		return "void"
	case PROC4_COMPOUND:
		return "compound"
	case OP4_ACCESS:
		return "access"
	case OP4_CLOSE:
		return "close"
	case OP4_COMMIT:
		return "commit"
	case OP4_CREATE:
		return "create"
	case OP4_DELEGPURGE:
		return "delegpurge"
	case OP4_DELEGRETURN:
		return "delegreturn"
	case OP4_GETATTR:
		return "getattr"
	case OP4_GETFH:
		return "getfh"
	case OP4_LINK:
		return "link"
	case OP4_LOCK:
		return "lock"
	case OP4_LOCKT:
		return "lockt"
	case OP4_LOCKU:
		return "locku"
	case OP4_LOOKUP:
		return "lookup"
	case OP4_LOOKUPP:
		return "lookupp"
	case OP4_NVERIFY:
		return "nverify"
	case OP4_OPEN:
		return "open"
	case OP4_OPENATTR:
		return "openattr"
	case OP4_OPEN_CONFIRM:
		return "open_confirm"
	case OP4_OPEN_DOWNGRADE:
		return "open_downgrade"
	case OP4_PUTFH:
		return "putfh"
	case OP4_PUTPUBFH:
		return "putpubfh"
	case OP4_PUTROOTFH:
		return "putrootfh"
	case OP4_READ:
		return "read"
	case OP4_READDIR:
		return "readdir"
	case OP4_READLINK:
		return "readlink"
	case OP4_REMOVE:
		return "remove"
	case OP4_RENAME:
		return "rename"
	case OP4_RENEW:
		return "renew"
	case OP4_RESTOREFH:
		return "restorefh"
	case OP4_SAVEFH:
		return "savefh"
	case OP4_SECINFO:
		return "secinfo"
	case OP4_SETATTR:
		return "setattr"
	case OP4_SETCLIENTID:
		return "setclientid"
	case OP4_SETCLIENTID_CONFIRM:
		return "setclientid_confirm"
	case OP4_VERIFY:
		return "verify"
	case OP4_WRITE:
		return "write"
	case OP4_RELEASE_LOCKOWNER:
		return "release_lockowner"
	// nfs-v4.1
	case OP4_EXCHANGE_ID:
		return "exchange_id"
	case OP4_CREATE_SESSION:
		return "create_session"
	case OP4_DESTROY_SESSION:
		return "destroy_session"
	case OP4_FREE_STATEID:
		return "free_stateid"
	case OP4_SECINFO_NO_NAME:
		return "secinfo_no_name"
	case OP4_SEQUENCE:
		return "sequence"
	case OP4_DESTROY_CLIENTID:
		return "destroy_clientid"
	case OP4_RECLAIM_COMPLETE:
		return "reclaim_complete"
	// nfs-v4.2
	case OP4_ALLOCATE:
		return "allocate"
	case OP4_COPY:
		return "copy"
	case OP4_COPY_NOTIFY:
		return "copy_notify"
	case OP4_DEALLOCATE:
		return "deallocate"
	case OP4_IO_ADVISE:
		return "io_advise"
	case OP4_LAYOUTERROR:
		return "layouterror"
	case OP4_LAYOUTSTATS:
		return "layoutstats"
	case OP4_OFFLOAD_CANCEL:
		return "offload_cancel"
	case OP4_OFFLOAD_STATUS:
		return "offload_status"
	case OP4_READ_PLUS:
		return "read_plus"
	case OP4_SEEK:
		return "seek"
	case OP4_WRITE_SAME:
		return "write_same"
	case OP4_CLONE:
		return "clone"
	case OP4_GETXATTR:
		return "getxattr"
	case OP4_SETXATTR:
		return "setxattr"
	case OP4_LISTXATTRS:
		return "listxattrs"
	case OP4_REMOVEXATTR:
		return "removexattr"
	case OP4_ILLEGAL:
		return "illegal"
	}
	return fmt.Sprintf("%d", proc)
}

const (
	NF4REG       = uint32(1)
	NF4DIR       = uint32(2)
	NF4BLK       = uint32(3)
	NF4CHR       = uint32(4)
	NF4LNK       = uint32(5)
	NF4SOCK      = uint32(6)
	NF4FIFO      = uint32(7)
	NF4ATTRDIR   = uint32(8)
	NF4NAMEDATTR = uint32(9)
)

const (
	FH4_PERSISTENT         = uint32(0x00000000)
	FH4_NOEXPIRE_WITH_OPEN = uint32(0x00000001)
	FH4_VOLATILE_ANY       = uint32(0x00000002)
	FH4_VOL_MIGRATION      = uint32(0x00000004)
	FH4_VOL_RENAME         = uint32(0x00000008)
)

const (
	ACCESS4_READ    = uint32(0x00000001)
	ACCESS4_LOOKUP  = uint32(0x00000002)
	ACCESS4_MODIFY  = uint32(0x00000004)
	ACCESS4_EXTEND  = uint32(0x00000008)
	ACCESS4_DELETE  = uint32(0x00000010)
	ACCESS4_EXECUTE = uint32(0x00000020)

	// rfc8276 — xattr access bits (NFSv4.2)
	ACCESS4_XAREAD  = uint32(0x00000040)
	ACCESS4_XAWRITE = uint32(0x00000080)
	ACCESS4_XALIST  = uint32(0x00000100)
)

// nfs-v4.1, rfc5661
const (
	EXCHGID4_FLAG_SUPP_MOVED_REFER = uint32(0x00000001)
	EXCHGID4_FLAG_SUPP_MOVED_MIGR  = uint32(0x00000002)

	EXCHGID4_FLAG_BIND_PRINC_STATEID = uint32(0x00000100)

	EXCHGID4_FLAG_USE_NON_PNFS = uint32(0x00010000)
	EXCHGID4_FLAG_USE_PNFS_MDS = uint32(0x00020000)
	EXCHGID4_FLAG_USE_PNFS_DS  = uint32(0x00040000)

	EXCHGID4_FLAG_MASK_PNFS = uint32(0x00070000)

	EXCHGID4_FLAG_UPD_CONFIRMED_REC_A = uint32(0x40000000)
	EXCHGID4_FLAG_CONFIRMED_R         = uint32(0x80000000)
)

// a generic result from op func.
type ResGenericRaw struct {
	Status uint32
	Reader io.Reader
}

type Fsid4 struct {
	Major uint64
	Minor uint64
}

type Specdata4 struct {
	D1 uint32
	D2 uint32
}

type FAttr4 struct {
	Mask []uint32 // bitmap4
	Vals []byte
}

type GETATTR4args struct {
	AttrRequest []uint32 // bitmap4
}

type GETATTR4resok struct {
	Attr *FAttr4
}

type GETATTR4res struct {
	Status uint32
	Ok     *GETATTR4resok // non-nil if status == NFS4_OK
}

type NfsClientId4 struct {
	Verifier uint64 // type: verifier4
	Id       []byte
}

type ClientAddr4 struct {
	NetId string
	Addr  string
}

type CbClient4 struct {
	CbProgram  uint32
	CbLocation *ClientAddr4
}

type SETCLIENTID4args struct {
	Client        *NfsClientId4
	Callback      *CbClient4
	CallbackIdent uint32
}

type SETCLIENTID4resok struct {
	ClientId           uint64 // type: clientid4
	SetClientIdConfirm uint64 // type: verifier4
}

type SETCLIENTID4res struct {
	Status   uint32
	Ok       *SETCLIENTID4resok // non-nil if status == NFS4_OK
	ErrInUse *ClientAddr4       // non-nil if status == NFS4ERR_CLID_INUSE
}

type SETCLIENTID_CONFIRM4args struct {
	ClientId uint64
	Verifier uint64
}

type SETCLIENTID_CONFIRM4res struct {
	Status uint32
}

type FileHandle4 []byte // max size: NFS4_FHSIZE=128

// func (fh FileHandle4) String() string {
// 	return hex.EncodeToString([]byte(fh))
// }

type PUTROOTFH4res struct {
	Status uint32
}

type PUTFH4args struct {
	Fh FileHandle4 // nfs_fh4
}

type PUTFH4res struct {
	Status uint32
}

type LOOKUP4args struct {
	ObjName string
}

type LOOKUP4res struct {
	Status uint32
}

type GETFH4args struct{}

type GETFH4resok struct {
	Fh FileHandle4 // nfs_fh4
}

type GETFH4res struct {
	Status uint32
	Ok     *GETFH4resok
}

type ACCESS4args struct {
	Access uint32
}

type ACCESS4resok struct {
	Supported uint32
	Access    uint32
}

type ACCESS4res struct {
	Status uint32
	Ok     *ACCESS4resok
}

type READDIR4args struct {
	Cookie      uint64
	CookieVerf  uint64   // opaque [8]
	DirCount    uint32   // max size of bytes of directory info.
	MaxCount    uint32   // max size of entire response(xdr header + READDIR4resok).
	AttrRequest []uint32 // bitmap4
}

type Entry4 struct {
	Cookie  uint64
	Name    string
	Attrs   *FAttr4
	HasNext bool
}

type DirList4 struct {
	HasEntries bool
	Entries    []*Entry4 // non-nil if HasEntries == true
	Eof        bool
}

type READDIR4resok struct {
	CookieVerf uint64
	Reply      *DirList4
}

type READDIR4res struct {
	Status uint32
	Ok     *READDIR4resok // non-nil if status == NFS4_OK
}

type SECINFO4args struct {
	Name string
}

const (
	// RPCSEC_GSS: https://datatracker.ietf.org/doc/html/rfc2203
	RPCSEC_GSS = uint32(6)
)

const (
	RPC_GSS_SVC_NONE      = uint32(1)
	RPC_GSS_SVC_INTEGRITY = uint32(2)
	RPC_GSS_SVC_PRIVACY   = uint32(3)
)

type RPCSecGssInfo struct {
	Oid     string
	Qop     uint32
	Service uint32 // RPC_GSS_SVC_*
}

type Secinfo4 struct {
	Flavor     uint32
	FlavorInfo *RPCSecGssInfo // non-nil if flavor == RPCSEC_GSS
}

type SECINFO4resok struct {
	Items []*Secinfo4
}

type SECINFO4res struct {
	Status uint32
	Ok     *SECINFO4resok // non-nil if status == NFS4_OK
}

type RENEW4args struct {
	ClientId uint64
}

type RENEW4res struct {
	Status uint32
}

type ClientOwner4 struct {
	Verifier uint64 // opaque [8]
	OwnerId  string
}

const (
	SP4_NONE      = uint32(0)
	SP4_MACH_CRED = uint32(1)
	SP4_SSV       = uint32(2)
)

type StateProtectOps4 struct {
	MustEnforce []uint32 // bitmap4
	MustAllow   []uint32 // bitmap4
}

type SsvSpParams4 struct {
	Ops           *StateProtectOps4
	HashAlgs      []string
	EncrAlgs      []string
	Window        uint32
	NumGssHandles uint32
}

type StateProtect4A struct {
	How       uint32
	MachOps   *StateProtectOps4 // non-nil if how == SP4_MACH_CRED
	SsvParams *SsvSpParams4     // non-nil if how == SP4_SSV
}

type EXCHANGE_ID4args struct {
	ClientOwner  *ClientOwner4
	Flags        uint32
	StateProtect *StateProtect4A
	ClientImplId []*NfsImplId4
}

type SsvProtInfo4 struct {
	Ops     *StateProtectOps4
	HashAlg uint32
	EncrAlg uint32
	SsvLen  uint32
	Window  uint32
	Handles []string
}

type StateProtect4R struct {
	How     uint32
	MachOps *StateProtectOps4 // non-nil if how == SP4_MACH_CRED
	SsvInfo *SsvProtInfo4     // non-nil if how == SP4_SSV
}

type ServerOwner4 struct {
	MinorId uint64
	MajorId string
}

type NfsTime4 struct {
	Seconds  uint64
	NSeconds uint32
}

type NfsImplId4 struct {
	Domain string // case-insensitive
	Name   string // case-sensitive
	Date   *NfsTime4
}

type EXCHANGE_ID4resok struct {
	ClientId     uint64
	SequenceId   uint32
	Flags        uint32
	StateProtect *StateProtect4R
	ServerOwner  *ServerOwner4
	ServerScope  string
	ServerImplId *NfsImplId4
}

type EXCHANGE_ID4res struct {
	Status uint32
	Ok     *EXCHANGE_ID4resok // non-nil if status == NFS4_OK
}

// CREATE_SESSION (RFC 5661 §18.36)

type ChannelAttrs4 struct {
	HeaderPadSize         uint32
	MaxRequestSize        uint32
	MaxResponseSize       uint32
	MaxResponseSizeCached uint32
	MaxOperations         uint32
	MaxRequests           uint32
	RdmaIrd               []uint32 // optional array, typically empty
}

// AuthSysParms4 is the AUTH_SYS (1) body of callback_sec_parms4 per RFC 5531.
type AuthSysParms4 struct {
	Stamp       uint32
	MachineName string
	Uid         uint32
	Gid         uint32
	Gids        []uint32
}

// CallbackSecParams4 is the callback_sec_parms4 discriminated union
// (RFC 5661 §18.36 / RFC 5531 AUTH_* flavors). Decoding requires a custom
// XdrUnmarshal because the body depends on CbSecFlavor.
type CallbackSecParams4 struct {
	CbSecFlavor uint32
	SysCred     *AuthSysParms4 // non-nil iff CbSecFlavor == AUTH_SYS
}

type CREATE_SESSION4args struct {
	ClientId          uint64
	Sequence          uint32
	Flags             uint32
	ForeChanAttrs     ChannelAttrs4
	BackChanAttrs     ChannelAttrs4
	CallbackProgram   uint32
	CallbackSecParams []CallbackSecParams4
}

type CREATE_SESSION4resok struct {
	SessionId     [16]byte
	Sequence      uint32
	Flags         uint32
	ForeChanAttrs ChannelAttrs4
	BackChanAttrs ChannelAttrs4
}

type CREATE_SESSION4res struct {
	Status uint32
	Ok     *CREATE_SESSION4resok // non-nil if Status == NFS4_OK
}

// SEQUENCE (RFC 5661 §18.46)

type SEQUENCE4args struct {
	SessionId     [16]byte
	SequenceId    uint32
	SlotId        uint32
	HighestSlotId uint32
	CacheThis     bool
}

type SEQUENCE4resok struct {
	SessionId           [16]byte
	SequenceId          uint32
	SlotId              uint32
	HighestSlotId       uint32
	TargetHighestSlotId uint32
	StatusFlags         uint32
}

type SEQUENCE4res struct {
	Status uint32
	Ok     *SEQUENCE4resok // non-nil if Status == NFS4_OK
}

// DESTROY_SESSION (RFC 5661 §18.37)

type DESTROY_SESSION4args struct {
	SessionId [16]byte
}

type DESTROY_SESSION4res struct {
	Status uint32
}

// DESTROY_CLIENTID (RFC 5661 §18.50)

type DESTROY_CLIENTID4args struct {
	ClientId uint64
}

type DESTROY_CLIENTID4res struct {
	Status uint32
}

// FREE_STATEID (RFC 5661 §18.38)

type FREE_STATEID4args struct {
	StateId StateId4
}

type FREE_STATEID4res struct {
	Status uint32
}

// RECLAIM_COMPLETE (RFC 5661 §18.51)

type RECLAIM_COMPLETE4args struct {
	OneFs bool
}

type RECLAIM_COMPLETE4res struct {
	Status uint32
}

type ChangeInfo4 struct {
	Atomic bool
	Before uint64
	After  uint64
}

type CREATE4args struct {
	ObjType     uint32
	LinkData    string     // if ObjType == NF4LNK
	DevData     *Specdata4 // if ObjType == NF4CHR | NF4BLK
	ObjName     string
	CreateAttrs *FAttr4
}

type CREATE4resok struct {
	CInfo   *ChangeInfo4
	AttrSet []uint32 // bitmap4
}

type CREATE4res struct {
	Status uint32
	Ok     *CREATE4resok // non-nil if status == NFS4_OK
}

type OpenOwner4 struct {
	ClientId uint64
	Owner    string
}

const (
	OPEN4_NOCREATE = uint32(0)
	OPEN4_CREATE   = uint32(1)
)

const (
	UNCHECKED4     = uint32(0)
	GUARDED4       = uint32(1)
	EXCLUSIVE4     = uint32(2)
	EXCLUSIVE4_1   = uint32(3) // rfc5661 §18.16 (v4.1+)
)

type CreateVerifier4_1 struct {
	Verifier [8]byte
	Attrs    *FAttr4
}

type CreateHow4 struct {
	CreateMode uint32 // UNCHECKED4 | GUARDED4 | EXCLUSIVE4 | EXCLUSIVE4_1

	CreateAttrs *FAttr4            // UNCHECKED4 / GUARDED4
	CreateVerf  uint64             // EXCLUSIVE4
	Excl41      *CreateVerifier4_1 // EXCLUSIVE4_1 (v4.1+)
}

const (
	CLAIM_NULL              = uint32(0)
	CLAIM_PREVIOUS          = uint32(1)
	CLAIM_DELEGATE_CUR      = uint32(2)
	CLAIM_DELEGATE_PREV     = uint32(3)
	CLAIM_FH                = uint32(4) // nfs-v4.1, rfc5661 §18.16
	CLAIM_DELEG_CUR_FH      = uint32(5) // nfs-v4.1
	CLAIM_DELEG_PREV_FH     = uint32(6) // nfs-v4.1
)

const (
	OPEN_DELEGATE_NONE  = uint32(0)
	OPEN_DELEGATE_READ  = uint32(1)
	OPEN_DELEGATE_WRITE = uint32(2)
)

type StateId4 struct {
	SeqId uint32
	Other [3]uint32
}

type OpenClaimDelegateCur4 struct {
	DelegateStateId *StateId4
	File            string
}

type OpenClaim4 struct {
	Claim uint32 // CLAIM_*

	File             string                 // if Claim == CLAIM_NULL
	DelegateType     uint32                 // OPEN_DELEGATE_*, if Claim == CLAIM_PREVIOUS
	DelegateCurInfo  *OpenClaimDelegateCur4 // if Clain == CLAIM_DELEGATE_CUR
	FileDelegatePrev string                 // if Claim == CLAIM_DELEGATE_PREV
}

type OPEN4args struct {
	SeqId       uint32
	ShareAccess uint32
	ShareDeny   uint32
	Owner       *OpenOwner4

	OpenHow uint32 // OPEN4_NOCREATE | OPEN4_CREATE

	CreateHow *CreateHow4 // if OpenHow == OPEN4_CREATE

	Claim *OpenClaim4
}

type OPENDG4args struct {
	OpenStateId *StateId4
	SeqId       uint32
	ShareAccess uint32
	ShareDeny   uint32
}

type NfsAce4 struct {
	Type       uint32
	Flag       uint32
	AccessMask uint32
	Who        string
}

type NfsModifiedLimit4 struct {
	NumBlocks     uint32
	BytesPerBlock uint32
}

type NfsSpaceLimit4 struct {
	LimitBy uint32

	FileSize  uint64             // if LimitBy == NFS_LIMIT_SIZE
	ModBlocks *NfsModifiedLimit4 // if LimitBy == NFS_LIMIT_BLOCKS
}

type OpenReadDelegation4 struct {
	StateId     *StateId4
	Recall      bool
	Permissions *NfsAce4
}

type OpenWriteDelegation4 struct {
	StateId     *StateId4
	Recall      bool
	SpaceLimit  *NfsSpaceLimit4
	Permissions *NfsAce4
}

type OpenDelegation4 struct {
	Type uint32

	Read  *OpenReadDelegation4  // if Type == OPEN_DELEGATE_READ
	Write *OpenWriteDelegation4 // if Type == OPEN_DELEGATE_WRITE
}

const (
	OPEN4_RESULT_CONFIRM        = uint32(0x00000002)
	OPEN4_RESULT_LOCKTYPE_POSIX = uint32(0x00000004)
)

type OPEN4resok struct {
	StateId    *StateId4
	CInfo      *ChangeInfo4
	Rflags     uint32 // OPEN4_RESULT_CONFIRM | OPEN4_RESULT_LOCKTYPE_POSIX
	AttrSet    []uint32
	Delegation *OpenDelegation4
}

type OPEN4res struct {
	Status uint32
	Ok     *OPEN4resok
}

type CLOSE4args struct {
	SeqId       uint32
	OpenStateId *StateId4
}

type CLOSE4res struct {
	Status uint32
	Ok     *StateId4 // non-nil if Status == NFS4_OK
}

type SETATTR4args struct {
	StateId *StateId4
	Attrs   *FAttr4
}

type SETATTR4res struct {
	Status  uint32
	AttrSet []uint32 // bitmap4
}

type REMOVE4args struct {
	Target string
}

type REMOVE4resok struct {
	CInfo *ChangeInfo4
}

type REMOVE4res struct {
	Status uint32
	Ok     *REMOVE4resok
}

type COMMIT4args struct {
	Offset uint64
	Count  uint32
}

type COMMIT4resok struct {
	Verifier uint64
}

type COMMIT4res struct {
	Status uint32
	Ok     *COMMIT4resok
}

/*

enum stable_how4 {
    UNSTABLE4       = 0,
    DATA_SYNC4      = 1,
    FILE_SYNC4      = 2
};

struct WRITE4args {
    stateid4        stateid;
    offset4         offset;
    stable_how4     stable;
    opaque          data<>;
};

*/

const (
	UNSTABLE4  = uint32(0)
	DATA_SYNC4 = uint32(1)
	FILE_SYNC4 = uint32(2)
)

type WRITE4args struct {
	StateId *StateId4
	Offset  uint64
	Stable  uint32 // USTABLE4 | DATA_SYNC4 | FILE_SYNC4
	Data    []byte
}

type WRITE4resok struct {
	Count     uint32
	Committed uint32 // USTABLE4 | DATA_SYNC4 | FILE_SYNC4
	WriteVerf uint64
}

type WRITE4res struct {
	Status uint32
	Ok     *WRITE4resok
}

type READ4args struct {
	StateId *StateId4
	Offset  uint64
	Count   uint32
}

type READ4resok struct {
	Eof  bool
	Data []byte
}

type READ4res struct {
	Status uint32
	Ok     *READ4resok
}

type SAVEFH4res struct {
	Status uint32
}

type RESTOREFH4res struct {
	Status uint32
}

type RENAME4args struct {
	OldName string
	NewName string
}

type RENAME4resok struct {
	SourceCInfo *ChangeInfo4
	TargetCInfo *ChangeInfo4
}

type RENAME4res struct {
	Status uint32
	Ok     *RENAME4resok
}

type LINK4args struct {
	NewName string
}

type LINK4resok struct {
	CInfo *ChangeInfo4
}

type LINK4res struct {
	Status uint32
	Ok     *LINK4resok
}

type READLINK4resok struct {
	Link string
}

type READLINK4res struct {
	Status uint32
	Ok     *READLINK4resok
}

// ---------- nfs-v4.2 (rfc7862) ----------

// SEEK (§15.11)

type SEEK4args struct {
	StateId StateId4
	Offset  uint64
	What    uint32
}

type SEEK4resok struct {
	Eof    bool
	Offset uint64
}

type SEEK4res struct {
	Status uint32
	Ok     *SEEK4resok
}

// COPY (§15.2). We implement synchronous, intra-server copy only. The
// source-servers list must be empty on the wire; see XdrUnmarshal in
// nfs/nfs_v4_xdr.go for the enforcement.

type WriteResponse4 struct {
	Callback  []StateId4 // empty for sync copy
	Count     uint64
	Committed uint32
	Verifier  [8]byte
}

type COPY4args struct {
	SrcStateId  StateId4
	DstStateId  StateId4
	SrcOffset   uint64
	DstOffset   uint64
	Count       uint64
	Consecutive bool
	Synchronous bool
	SrcServers  Netloc4List // must be empty on decode
}

type COPY4resok struct {
	Response    WriteResponse4
	Consecutive bool
	Synchronous bool
}

type COPY4res struct {
	Status uint32
	Ok     *COPY4resok
}

// Netloc4List is the marker type for the "source servers" field of
// COPY4args. A custom XdrUnmarshal rejects non-empty lists so the
// reflection-based decoder doesn't try to walk the discriminated
// netloc4 union (which we don't implement).
type Netloc4List struct{}

// ALLOCATE / DEALLOCATE (§15.4 / §15.5). Decoded only so the reader
// stays aligned on the NFS4ERR_NOTSUPP fallback path.

type ALLOCATE4args struct {
	StateId StateId4
	Offset  uint64
	Length  uint64
}

type DEALLOCATE4args = ALLOCATE4args

// ---------- rfc8276 xattrs ----------

type GETXATTR4args struct {
	Name string
}

type GETXATTR4resok struct {
	Value []byte
}

type GETXATTR4res struct {
	Status uint32
	Ok     *GETXATTR4resok
}

type SETXATTR4args struct {
	Option uint32
	Name   string
	Value  []byte
}

type SETXATTR4res struct {
	Status uint32
	Info   *ChangeInfo4
}

type LISTXATTRS4args struct {
	Cookie   uint64
	MaxCount uint32
}

type LISTXATTRS4resok struct {
	Cookie uint64
	Names  []string
	Eof    bool
}

type LISTXATTRS4res struct {
	Status uint32
	Ok     *LISTXATTRS4resok
}

type REMOVEXATTR4args struct {
	Name string
}

type REMOVEXATTR4res struct {
	Status uint32
	Info   *ChangeInfo4
}
