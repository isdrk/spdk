/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/fsdev.h"
#include "spdk/rpc.h"
#include "spdk/env.h"
#include "spdk/util.h"
#include "spdk/thread.h"
#include "spdk/likely.h"
#include "spdk/fuse_dispatcher.h"
#include "spdk/rmem.h"
#include "linux/fuse_kernel.h"

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

/* TODO: values, see https://libfuse.github.io/doxygen/structfuse__conn__info.html */
#define DEFAULT_TIME_GRAN 1
#define DEFAULT_MAX_BACKGROUND 0xffff
#define DEFAULT_CONGESTION_THRESHOLD 0xffff
#define DEFAULT_MAX_READAHEAD 0x00020000
#define OFFSET_MAX 0x7fffffffffffffffLL

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/*
 * NOTE: It appeared that the open flags have different values on the different HW architechtures.
 *
 * This code handles the open flags translation in case they're originated from a platform with
 * a different HW architecture.
 *
 * Currently supported:
 *  - X86
 *  - X86_64
 *  - ARM
 *  - ARM64
 */
/* See https://lxr.missinglinkelectronics.com/linux/arch/arm/include/uapi/asm/fcntl.h */
#define ARM_O_DIRECTORY      040000 /* must be a directory */
#define ARM_O_NOFOLLOW      0100000 /* don't follow links */
#define ARM_O_DIRECT        0200000 /* direct disk access hint - currently ignored */
#define ARM_O_LARGEFILE     0400000

/* See https://lxr.missinglinkelectronics.com/linux/include/uapi/asm-generic/fcntl.h */
#define X86_O_DIRECT        00040000        /* direct disk access hint */
#define X86_O_LARGEFILE     00100000
#define X86_O_DIRECTORY     00200000        /* must be a directory */
#define X86_O_NOFOLLOW      00400000        /* don't follow links */

static inline bool
fsdev_d2h_open_flags(enum spdk_fuse_arch fuse_arch, uint32_t flags, uint32_t *translated_flags)
{
	bool res = true;

	*translated_flags = flags;

	/* NOTE: we always check the original flags to avoid situation where the arch and the native flags
	 * overlap and previously set native flag could be interpreted as original arch flag.
	 */
#define REPLACE_FLAG(arch_flag, native_flag) \
	do { \
		if (flags & (arch_flag)) { \
			*translated_flags &= ~(arch_flag); \
			*translated_flags |= (native_flag); \
		} \
	} while(0)

	switch (fuse_arch) {
	case SPDK_FUSE_ARCH_NATIVE:
#if defined(__x86_64__) || defined(__i386__)
	case SPDK_FUSE_ARCH_X86:
	case SPDK_FUSE_ARCH_X86_64:
#endif
#if defined(__aarch64__) || defined(__arm__)
	case SPDK_FUSE_ARCH_ARM:
	case SPDK_FUSE_ARCH_ARM64:
#endif
		/* No translation required */
		break;
#if defined(__x86_64__) || defined(__i386__)
	case SPDK_FUSE_ARCH_ARM:
	case SPDK_FUSE_ARCH_ARM64:
		/* Relace the ARM-specific flags with the native ones */
		REPLACE_FLAG(ARM_O_DIRECTORY, O_DIRECTORY);
		REPLACE_FLAG(ARM_O_NOFOLLOW, O_NOFOLLOW);
		REPLACE_FLAG(ARM_O_DIRECT, O_DIRECT);
		REPLACE_FLAG(ARM_O_LARGEFILE, O_LARGEFILE);
		break;
#endif
#if defined(__aarch64__) || defined(__arm__)
	case SPDK_FUSE_ARCH_X86:
	case SPDK_FUSE_ARCH_X86_64:
		/* Relace the X86-specific flags with the native ones */
		REPLACE_FLAG(X86_O_DIRECTORY, O_DIRECTORY);
		REPLACE_FLAG(X86_O_NOFOLLOW, O_NOFOLLOW);
		REPLACE_FLAG(X86_O_DIRECT, O_DIRECT);
		REPLACE_FLAG(X86_O_LARGEFILE, O_LARGEFILE);
		break;
#endif
	default:
		SPDK_ERRLOG("Unsupported FUSE arch: %d\n", fuse_arch);
		assert(0);
		res = false;
		break;
	}

#undef REPLACE_FLAG

	return res;
}

struct fuse_forget_data {
	uint64_t ino;
	uint64_t nlookup;
};

struct iov_offs {
	size_t iov_offs;
	size_t buf_offs;
};

struct fuse_io {
	/** For SG buffer cases, array of iovecs for input. */
	struct iovec *in_iov;

	/** For SG buffer cases, number of iovecs in in_iov array. */
	int in_iovcnt;

	/** For SG buffer cases, array of iovecs for output. */
	struct iovec *out_iov;

	/** For SG buffer cases, number of iovecs in out_iov array. */
	int out_iovcnt;

	struct iov_offs in_offs;
	struct iov_offs out_offs;

	spdk_fuse_dispatcher_submit_cpl_cb cpl_cb;
	void *cpl_cb_arg;
	struct spdk_io_channel *ch;
	struct spdk_fuse_dispatcher *disp;

	struct fuse_in_header hdr;
	bool in_hdr_with_data;

	union {
		struct {
			struct spdk_thread *thread;
			struct fuse_init_in *in;
			bool legacy_in;
			struct spdk_fsdev_mount_opts opts;
			size_t out_len;
			int error;
		} init;
		struct {
			bool plus;
			uint32_t size;
			char *writep;
			uint32_t bytes_written;
		} readdir;
		struct {
			uint32_t to_forget;
			int status;
		} batch_forget;

		struct {
			/* File handle of the poll event operation. */
			uint64_t fhandle;

			/* Requested event mask for poll operation. */
			uint32_t events;
		} poll;

		struct {
			int status;
		} fsdev_close;
		struct {
			/* Input lock for setlkw operation. */
			struct spdk_fsdev_file_lock lock;

			/* Input file handle for setlkw operation. */
			uint64_t fhandle;

			/* Input owner for setlkw operation. */
			uint64_t owner;
		} setlkw;
		struct {
			/*
			 * The flags in the ioctl() request. Used in completion
			 * to populate the out that is done differenly for the
			 * "unrestricted".
			 */
			uint32_t flags;

			/*
			 * Saved input out_size and used in compeltion cb
			 * for restricted ioctl().
			 */
			uint32_t out_size;

			/*
			 * Input in and out iovs and counts. These are passed down
			 * to the FSDEV and have to stay alive until the fuse_io
			 * completion.
			 *
			 * Alloctaed in do_ioctl() and freed in the ioctl completion.
			 * when the data is sent back to the kernel.
			 */
			struct iovec *in_iov;
			struct iovec *out_iov;
			uint32_t in_iovcnt;
			uint32_t out_iovcnt;
		} ioctl;
	} u;
};

struct fuse_disp_recovery_data {
	uint32_t proto_major;
	uint32_t proto_minor;
	uint64_t root_fobject;
};

struct spdk_fuse_dispatcher {
	/**
	 * fsdev descriptor
	 */
	struct spdk_fsdev_desc *desc;

	/**
	 * Major version of the protocol (read-only)
	 */
	uint32_t proto_major;

	/**
	 * Minor version of the protocol (read-only)
	 */
	uint32_t proto_minor;

	/**
	 * FUSE request source's architecture
	 */
	enum spdk_fuse_arch fuse_arch;

	/**
	 * Root file object
	 */
	struct spdk_fsdev_file_object *root_fobject;

	/**
	 * Negotiated mount flags.
	 */
	uint32_t mount_flags;

	/**
	 * Recovery memory pool.
	 */
	struct spdk_rmem_pool *rmem_pool;

	/**
	 * Recovery memory entry (data).
	 */
	struct spdk_rmem_entry *rmem_data;

	/**
	 * Callback to handle FUSE_NOTIFY_REPLY requests.
	 */
	spdk_fuse_dispatcher_notify_reply_cb notify_reply_cb;

	/**
	 * Context for notify_reply_cb.
	 */
	void *notify_reply_cb_arg;
};

struct fuse_notify_reply_in {
	int32_t error; /* 0 on success, negated errno for error */
	uint32_t padding;
};

static inline const char *
fuse_dispatcher_name(struct spdk_fuse_dispatcher *disp)
{
	return spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(disp->desc));
}

static inline uint64_t
file_ino(struct spdk_fuse_dispatcher *disp, const struct spdk_fsdev_file_object *fobject)
{
	return (disp->root_fobject == fobject) ? FUSE_ROOT_ID : (uint64_t)(uintptr_t)fobject;
}

static struct spdk_fsdev_file_object *
ino_to_object(struct fuse_io *fuse_io, uint64_t ino)
{
	return (ino == FUSE_ROOT_ID) ?
	       fuse_io->disp->root_fobject :
	       (struct spdk_fsdev_file_object *)(uintptr_t)ino;
}

static struct spdk_fsdev_file_object *
file_object(struct fuse_io *fuse_io)
{
	return ino_to_object(fuse_io, fuse_io->hdr.nodeid);
}

static inline uint64_t
file_fh(const struct spdk_fsdev_file_handle *fhandle)
{
	return (uint64_t)(uintptr_t)fhandle;
}

static struct spdk_fsdev_file_handle *
file_handle(uint64_t fh)
{
	return (struct spdk_fsdev_file_handle *)(uintptr_t)fh;
}

static inline uint16_t
fsdev_io_d2h_u16(struct spdk_fuse_dispatcher *disp, uint16_t v)
{
	return v;
}

static inline uint16_t
fsdev_io_h2d_u16(struct spdk_fuse_dispatcher *disp, uint16_t v)
{
	return v;
}

static inline uint32_t
fsdev_io_d2h_u32(struct spdk_fuse_dispatcher *disp, uint32_t v)
{
	return v;
}

static inline uint32_t
fsdev_io_h2d_u32(struct spdk_fuse_dispatcher *disp, uint32_t v)
{
	return v;
}

static inline int32_t
fsdev_io_d2h_i32(struct spdk_fuse_dispatcher *disp, int32_t v)
{
	return v;
}

static inline int32_t
fsdev_io_h2d_i32(struct spdk_fuse_dispatcher *disp, int32_t v)
{
	return v;
}

static inline uint64_t
fsdev_io_d2h_u64(struct spdk_fuse_dispatcher *disp, uint64_t v)
{
	return v;
}

static inline uint64_t
fsdev_io_h2d_u64(struct spdk_fuse_dispatcher *disp, uint64_t v)
{
	return v;
}

static inline uint32_t
fsdev_io_proto_minor(struct fuse_io *fuse_io)
{
	return fuse_io->disp->proto_minor;
}

static inline void *
_iov_arr_get_buf_info(struct iovec *iovs, size_t cnt, struct iov_offs *offs, size_t *size)
{
	struct iovec *iov;

	assert(offs->iov_offs <= cnt);

	if (offs->iov_offs == cnt) {
		assert(!offs->buf_offs);
		*size = 0;
		return NULL;
	}

	iov = &iovs[offs->iov_offs];

	assert(offs->buf_offs < iov->iov_len);

	*size = iov->iov_len - offs->buf_offs;

	return ((char *)iov->iov_base) + offs->buf_offs;
}

static inline void *
_iov_arr_get_buf(struct iovec *iovs, size_t cnt, struct iov_offs *offs, size_t size,
		 const char *direction)
{
	char *arg_buf;
	size_t arg_size;

	arg_buf = _iov_arr_get_buf_info(iovs, cnt, offs, &arg_size);
	if (!arg_buf) {
		SPDK_INFOLOG(fuse_dispatcher, "Requested %s buffer is already consumed or not existing: "
			     "count=%d, attached=%zu:%zu\n", direction, (int)cnt, offs->iov_offs, offs->buf_offs);
		return NULL;
	}

	if (!arg_size) {
		SPDK_INFOLOG(fuse_dispatcher, "Requested %s buffer attached at %zu:%zu has zero length\n",
			     direction, offs->iov_offs, offs->buf_offs);
		return NULL;
	}

	if (size > arg_size) {
		SPDK_INFOLOG(fuse_dispatcher, "Requested %s buffer is too small (expected size = %zu > actual "
			     "size = %zu) at %zu:%zu\n", direction, size, arg_size, offs->iov_offs, offs->buf_offs);
		return NULL;
	}

	if (size == arg_size) {
		offs->iov_offs++;
		offs->buf_offs = 0;
	} else {
		offs->buf_offs += size;
	}

	return arg_buf;
}

static inline const char *
_fsdev_io_in_arg_get_str(struct fuse_io *fuse_io)
{
	char *arg_buf;
	size_t arg_size, len;

	arg_buf = _iov_arr_get_buf_info(fuse_io->in_iov, fuse_io->in_iovcnt, &fuse_io->in_offs,
					&arg_size);
	if (!arg_buf) {
		SPDK_ERRLOG("Requested IN string buffer is already consumed or not existing: count=%d, attached=%zu:%zu\n",
			    fuse_io->in_iovcnt, fuse_io->in_offs.iov_offs, fuse_io->in_offs.buf_offs);
		return NULL;
	}

	len = strnlen(arg_buf, arg_size);
	if (len == arg_size) {
		SPDK_ERRLOG("No string or bad string attached at %zu:%zu\n", fuse_io->in_offs.iov_offs,
			    fuse_io->in_offs.buf_offs);
		return NULL;
	}

	fuse_io->in_offs.buf_offs += len + 1;

	if (len + 1 == arg_size) {
		fuse_io->in_offs.iov_offs++;
		fuse_io->in_offs.buf_offs = 0;
	}

	return arg_buf;
}

static inline void *
_fsdev_io_in_arg_get_buf(struct fuse_io *fuse_io, size_t size)
{
	return _iov_arr_get_buf(fuse_io->in_iov, fuse_io->in_iovcnt, &fuse_io->in_offs, size, "IN");
}


static inline void *
_fsdev_io_out_arg_get_buf(struct fuse_io *fuse_io, size_t size)
{
	return _iov_arr_get_buf(fuse_io->out_iov, fuse_io->out_iovcnt, &fuse_io->out_offs, size,
				"OUT");
}

static bool
_fuse_op_requires_reply(uint32_t opcode)
{
	switch (opcode) {
	case FUSE_FORGET:
	case FUSE_BATCH_FORGET:
	case FUSE_NOTIFY_REPLY:
		return false;
	default:
		return true;
	}
}

static void
fuse_dispatcher_update_rmem(struct spdk_fuse_dispatcher *disp)
{
	if (disp->rmem_data) {
		struct fuse_disp_recovery_data data = {
			.proto_major = disp->proto_major,
			.proto_minor = disp->proto_minor,
			.root_fobject = (uint64_t)(uintptr_t)disp->root_fobject,
		};

		spdk_rmem_entry_write(disp->rmem_data, &data);
	}
}

static void
fsdev_attr_to_fuse(struct fuse_io *fuse_io, struct spdk_fsdev_file_object *fobject,
		   const struct spdk_fsdev_file_attr *attr, struct fuse_attr *fattr)
{
	fattr->ino	= fsdev_io_h2d_u64(fuse_io->disp, attr->ino);
	fattr->mode	= fsdev_io_h2d_u32(fuse_io->disp, attr->mode);
	fattr->nlink	= fsdev_io_h2d_u32(fuse_io->disp, attr->nlink);
	fattr->uid	= fsdev_io_h2d_u32(fuse_io->disp, attr->uid);
	fattr->gid	= fsdev_io_h2d_u32(fuse_io->disp, attr->gid);
	fattr->rdev	= fsdev_io_h2d_u32(fuse_io->disp, attr->rdev);
	fattr->size	= fsdev_io_h2d_u64(fuse_io->disp, attr->size);
	fattr->blksize	= fsdev_io_h2d_u32(fuse_io->disp, attr->blksize);
	fattr->blocks	= fsdev_io_h2d_u64(fuse_io->disp, attr->blocks);
	fattr->atime	= fsdev_io_h2d_u64(fuse_io->disp, attr->atime);
	fattr->mtime	= fsdev_io_h2d_u64(fuse_io->disp, attr->mtime);
	fattr->ctime	= fsdev_io_h2d_u64(fuse_io->disp, attr->ctime);
	fattr->atimensec = fsdev_io_h2d_u32(fuse_io->disp, attr->atimensec);
	fattr->mtimensec = fsdev_io_h2d_u32(fuse_io->disp, attr->mtimensec);
	fattr->ctimensec = fsdev_io_h2d_u32(fuse_io->disp, attr->ctimensec);
}

static uint32_t
calc_timeout_sec(uint32_t ms)
{
	return ms / 1000;
}

static uint32_t
calc_timeout_nsec(uint32_t ms)
{
	return (ms % 1000) * 1000000;
}

static void
fill_entry(struct fuse_io *fuse_io, struct fuse_entry_out *arg,
	   struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	arg->nodeid = fsdev_io_h2d_u64(fuse_io->disp, file_ino(fuse_io->disp, fobject));
	arg->generation = 0;
	arg->entry_valid = fsdev_io_h2d_u64(fuse_io->disp, calc_timeout_sec(attr->valid_ms));
	arg->entry_valid_nsec = fsdev_io_h2d_u32(fuse_io->disp, calc_timeout_nsec(attr->valid_ms));
	arg->attr_valid = fsdev_io_h2d_u64(fuse_io->disp, calc_timeout_sec(attr->valid_ms));
	arg->attr_valid_nsec = fsdev_io_h2d_u32(fuse_io->disp, calc_timeout_nsec(attr->valid_ms));
	fsdev_attr_to_fuse(fuse_io, fobject, attr, &arg->attr);
}

static void
fill_open(struct fuse_io *fuse_io, struct fuse_open_out *arg,
	  struct spdk_fsdev_file_handle *fhandle)
{
	arg->fh = fsdev_io_h2d_u64(fuse_io->disp, file_fh(fhandle));
	arg->open_flags = fsdev_io_h2d_u64(fuse_io->disp, FOPEN_DIRECT_IO);
}

static void
convert_statfs(struct fuse_io *fuse_io, const struct spdk_fsdev_file_statfs *statfs,
	       struct fuse_kstatfs *kstatfs)
{
	kstatfs->bsize	 = fsdev_io_h2d_u32(fuse_io->disp, statfs->bsize);
	kstatfs->frsize	 = fsdev_io_h2d_u32(fuse_io->disp, statfs->frsize);
	kstatfs->blocks	 = fsdev_io_h2d_u64(fuse_io->disp, statfs->blocks);
	kstatfs->bfree	 = fsdev_io_h2d_u64(fuse_io->disp, statfs->bfree);
	kstatfs->bavail	 = fsdev_io_h2d_u64(fuse_io->disp, statfs->bavail);
	kstatfs->files	 = fsdev_io_h2d_u64(fuse_io->disp, statfs->files);
	kstatfs->ffree	 = fsdev_io_h2d_u64(fuse_io->disp, statfs->ffree);
	kstatfs->namelen = fsdev_io_h2d_u32(fuse_io->disp, statfs->namelen);
}

static struct fuse_out_header *
fuse_dispatcher_fill_out_hdr(struct fuse_io *fuse_io, size_t out_len, int error)
{
	struct fuse_out_header *hdr;
	struct iovec *out;
	uint32_t len;

	assert(fuse_io->out_iovcnt >= 1);
	assert(error <= 0);

	out = fuse_io->out_iov;

	if (out->iov_len < sizeof(*hdr)) {
		SPDK_ERRLOG("Bad out header len: %zu < %zu\n", out->iov_len, sizeof(*hdr));
		return NULL;
	}

	if (error < -1000) {
		SPDK_ERRLOG("Bad completion error value: %" PRIu32 "\n", error);
		return NULL;
	}

	len = sizeof(*hdr) + out_len;

	hdr = out->iov_base;
	memset(hdr, 0, sizeof(*hdr));

	hdr->unique = fsdev_io_h2d_u64(fuse_io->disp, fuse_io->hdr.unique);
	hdr->error = fsdev_io_h2d_i32(fuse_io->disp, error);
	hdr->len = fsdev_io_h2d_u32(fuse_io->disp, len);

	return hdr;
}

static void
fuse_dispatcher_io_complete_final(struct fuse_io *fuse_io, int error)
{
	spdk_fuse_dispatcher_submit_cpl_cb cpl_cb = fuse_io->cpl_cb;
	void *cpl_cb_arg = fuse_io->cpl_cb_arg;

	cpl_cb(cpl_cb_arg, error);
}

static void
fuse_dispatcher_io_complete(struct fuse_io *fuse_io, uint32_t out_len, int error)
{
	struct fuse_out_header *hdr = fuse_dispatcher_fill_out_hdr(fuse_io, out_len, error);

	assert(_fuse_op_requires_reply(fuse_io->hdr.opcode));

	if (!hdr) {
		SPDK_ERRLOG("Completion failed: cannot fill out header\n");
		return;
	}

	SPDK_DEBUGLOG(fuse_dispatcher,
		      "Completing IO#%" PRIu64 " (err=%d, out_len=%" PRIu32 ")\n",
		      fuse_io->hdr.unique, error, out_len);

	fuse_dispatcher_io_complete_final(fuse_io, error);
}

static void
fuse_dispatcher_io_copy_and_complete(struct fuse_io *fuse_io, const void *out, uint32_t out_len,
				     int error)
{
	if (out && out_len) {
		void *buf = _fsdev_io_out_arg_get_buf(fuse_io, out_len);
		if (buf) {
			memcpy(buf, out, out_len);
		} else {
			SPDK_ERRLOG("Completion failed: cannot get buf to copy %" PRIu32 " bytes\n", out_len);
			error = -EINVAL;
			out_len = 0;
		}
	}

	fuse_dispatcher_io_complete(fuse_io, out_len, error);
}

static void
fuse_dispatcher_io_complete_none(struct fuse_io *fuse_io, int err)
{
	SPDK_DEBUGLOG(fuse_dispatcher, "Completing IO#%" PRIu64 "(err=%d)\n",
		      fuse_io->hdr.unique, err);
	fuse_dispatcher_io_complete_final(fuse_io, err);
}

static void
fuse_dispatcher_io_complete_ok(struct fuse_io *fuse_io, uint32_t out_len)
{
	fuse_dispatcher_io_complete(fuse_io, out_len, 0);
}

static void
fuse_dispatcher_io_complete_err(struct fuse_io *fuse_io, int err)
{
	fuse_dispatcher_io_complete(fuse_io, 0, err);
}

static void
fuse_dispatcher_io_complete_entry(struct fuse_io *fuse_io, struct spdk_fsdev_file_object *fobject,
				  const struct spdk_fsdev_file_attr *attr)
{
	struct fuse_entry_out arg;
	size_t size = fsdev_io_proto_minor(fuse_io) < 9 ?
		      FUSE_COMPAT_ENTRY_OUT_SIZE : sizeof(arg);

	memset(&arg, 0, sizeof(arg));
	fill_entry(fuse_io, &arg, fobject, attr);

	fuse_dispatcher_io_copy_and_complete(fuse_io, &arg, size, 0);
}

static void
fuse_dispatcher_io_complete_open(struct fuse_io *fuse_io, struct spdk_fsdev_file_handle *fhandle)
{
	struct fuse_open_out *arg;

	arg = _fsdev_io_out_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_open_out\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fill_open(fuse_io, arg, fhandle);

	fuse_dispatcher_io_complete_ok(fuse_io, sizeof(*arg));
}

static void
fuse_dispatcher_io_complete_create(struct fuse_io *fuse_io, struct spdk_fsdev_file_object *fobject,
				   const struct spdk_fsdev_file_attr *attr,
				   struct spdk_fsdev_file_handle *fhandle)
{
	char buf[sizeof(struct fuse_entry_out) + sizeof(struct fuse_open_out)];
	size_t entrysize = fsdev_io_proto_minor(fuse_io) < 9 ?
			   FUSE_COMPAT_ENTRY_OUT_SIZE : sizeof(struct fuse_entry_out);
	struct fuse_entry_out *earg = (struct fuse_entry_out *) buf;
	struct fuse_open_out *oarg = (struct fuse_open_out *)(buf + entrysize);

	memset(buf, 0, sizeof(buf));
	fill_entry(fuse_io, earg, fobject, attr);
	fill_open(fuse_io, oarg, fhandle);

	fuse_dispatcher_io_copy_and_complete(fuse_io, buf, entrysize + sizeof(struct fuse_open_out), 0);
}

static void
fuse_dispatcher_io_complete_xattr(struct fuse_io *fuse_io, uint32_t count)
{
	struct fuse_getxattr_out *arg;

	arg = _fsdev_io_out_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_getxattr_out\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	arg->size = fsdev_io_h2d_i32(fuse_io->disp, count);

	fuse_dispatcher_io_complete_ok(fuse_io, sizeof(*arg));
}

static void
fuse_dispatcher_io_complete_write(struct fuse_io *fuse_io, uint32_t data_size, int error)
{
	struct fuse_write_out *arg;

	arg = _fsdev_io_out_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_write_out\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	arg->size = fsdev_io_d2h_u32(fuse_io->disp, data_size);

	fuse_dispatcher_io_complete(fuse_io, sizeof(*arg), error);
}

static void
fuse_dispatcher_io_complete_statfs(struct fuse_io *fuse_io,
				   const struct spdk_fsdev_file_statfs *statfs)
{
	struct fuse_statfs_out arg;
	size_t size = fsdev_io_proto_minor(fuse_io) < 4 ?
		      FUSE_COMPAT_STATFS_SIZE : sizeof(arg);

	memset(&arg, 0, sizeof(arg));
	convert_statfs(fuse_io, statfs, &arg.st);

	return fuse_dispatcher_io_copy_and_complete(fuse_io, &arg, size, 0);
}

static void
fuse_dispatcher_io_complete_attr(struct fuse_io *fuse_io, const struct spdk_fsdev_file_attr *attr)
{
	struct fuse_attr_out arg;
	size_t size = fsdev_io_proto_minor(fuse_io) < 9 ?
		      FUSE_COMPAT_ATTR_OUT_SIZE : sizeof(arg);

	memset(&arg, 0, sizeof(arg));
	arg.attr_valid = fsdev_io_h2d_u64(fuse_io->disp, calc_timeout_sec(attr->valid_ms));
	arg.attr_valid_nsec = fsdev_io_h2d_u32(fuse_io->disp, calc_timeout_nsec(attr->valid_ms));
	fsdev_attr_to_fuse(fuse_io, file_object(fuse_io), attr, &arg.attr);

	fuse_dispatcher_io_copy_and_complete(fuse_io, &arg, size, 0);
}

static void
fuse_dispatcher_io_complete_lseek(struct fuse_io *fuse_io, off_t offset)
{
	struct fuse_lseek_out arg;
	size_t size = sizeof(arg);

	arg.offset = fsdev_io_h2d_u64(fuse_io->disp, offset);

	fuse_dispatcher_io_copy_and_complete(fuse_io, &arg, size, 0);
}

static uint32_t
fsdev_events_to_fuse(uint32_t spdk_events)
{
	uint32_t result = 0;

	if (spdk_events & SPDK_FSDEV_POLLIN) {
		result |= POLLIN;
	}
	if (spdk_events & SPDK_FSDEV_POLLOUT) {
		result |= POLLOUT;
	}
	if (spdk_events & SPDK_FSDEV_POLLPRI) {
		result |= POLLPRI;
	}
	if (spdk_events & SPDK_FSDEV_POLLERR) {
		result |= POLLERR;
	}
	if (spdk_events & SPDK_FSDEV_POLLHUP) {
		result |= POLLHUP;
	}
	if (spdk_events & SPDK_FSDEV_POLLNVAL) {
		result |= POLLNVAL;
	}
	if (spdk_events & SPDK_FSDEV_POLLRDNORM) {
		result |= POLLRDNORM;
	}
	if (spdk_events & SPDK_FSDEV_POLLRDBAND) {
		result |= POLLRDBAND;
	}
	if (spdk_events & SPDK_FSDEV_POLLWRNORM) {
		result |= POLLWRNORM;
	}
	if (spdk_events & SPDK_FSDEV_POLLWRBAND) {
		result |= POLLWRBAND;
	}

	return result;
}

static uint32_t
fuse_events_to_fsdev(uint32_t events)
{
	uint32_t result = 0;

	if (events & POLLIN) {
		result |= SPDK_FSDEV_POLLIN;
	}
	if (events & POLLOUT) {
		result |= SPDK_FSDEV_POLLOUT;
	}
	if (events & POLLPRI) {
		result |= SPDK_FSDEV_POLLPRI;
	}
	if (events & POLLERR) {
		result |= SPDK_FSDEV_POLLERR;
	}
	if (events & POLLHUP) {
		result |= SPDK_FSDEV_POLLHUP;
	}
	if (events & POLLNVAL) {
		result |= SPDK_FSDEV_POLLNVAL;
	}
	if (events & POLLRDNORM) {
		result |= SPDK_FSDEV_POLLRDNORM;
	}
	if (events & POLLRDBAND) {
		result |= SPDK_FSDEV_POLLRDBAND;
	}
	if (events & POLLWRNORM) {
		result |= SPDK_FSDEV_POLLWRNORM;
	}
	if (events & POLLWRBAND) {
		result |= SPDK_FSDEV_POLLWRBAND;
	}

	return result;
}

static void
fuse_dispatcher_io_complete_poll(struct fuse_io *fuse_io, uint32_t revents)
{
	struct fuse_poll_out *arg = _fsdev_io_out_arg_get_buf(fuse_io, sizeof(*arg));

	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_poll_out\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}
	arg->revents = fsdev_io_h2d_u32(fuse_io->disp, fsdev_events_to_fuse(revents));

	fuse_dispatcher_io_complete_ok(fuse_io, sizeof(*arg));
}
#if DEBUG
static const char *
fuse_lock_type_to_str(uint32_t fuse_lock_type)
{
	if (fuse_lock_type == F_RDLCK) {
		return "F_RDLCK";
	} else if (fuse_lock_type == F_WRLCK) {
		return "F_WRLCK";
	} else if (fuse_lock_type == F_UNLCK) {
		return "F_UNLCK";
	} else {
		return "UNKNOWN";
	}
}
#endif

static int
fuse_to_fsdev_file_lock(struct fuse_io *fuse_io, const struct fuse_file_lock *fuse_lock,
			struct spdk_fsdev_file_lock *fsdev_lock)
{
	switch (fsdev_io_d2h_u32(fuse_io->disp, fuse_lock->type)) {
	case F_RDLCK:
		fsdev_lock->type = SPDK_FSDEV_RDLCK;
		break;
	case F_WRLCK:
		fsdev_lock->type = SPDK_FSDEV_WRLCK;
		break;
	case F_UNLCK:
		fsdev_lock->type = SPDK_FSDEV_UNLCK;
		break;
	default:
		SPDK_ERRLOG("Invalid lock type %d during fuse to fsdev lock conversion.\n",
			    fsdev_io_d2h_u32(fuse_io->disp, fuse_lock->type));
		return -EINVAL;
	}
	fsdev_lock->start = fsdev_io_d2h_u64(fuse_io->disp, fuse_lock->start);
	fsdev_lock->end = fsdev_io_d2h_u64(fuse_io->disp, fuse_lock->end);
	if (fsdev_lock->end == 0) {
		fsdev_lock->end = SPDK_FSDEV_FILE_LOCK_END_OF_FILE;
	}
	fsdev_lock->pid = fsdev_io_d2h_u32(fuse_io->disp, fuse_lock->pid);

	SPDK_DEBUGLOG(fuse_dispatcher, "fuse -> fsdev lock type=%x, start=%lu, end=%lu, pid=%u\n",
		      fsdev_lock->type, fsdev_lock->start, fsdev_lock->end, fsdev_lock->pid);
	return 0;
}

static int
fsdev_file_lock_to_fuse(struct fuse_io *fuse_io, const struct spdk_fsdev_file_lock *fsdev_lock,
			struct fuse_file_lock *fuse_lock)
{
	switch (fsdev_lock->type) {
	case SPDK_FSDEV_RDLCK:
		fuse_lock->type = fsdev_io_h2d_u32(fuse_io->disp, F_RDLCK);
		break;
	case SPDK_FSDEV_WRLCK:
		fuse_lock->type = fsdev_io_h2d_u32(fuse_io->disp, F_WRLCK);
		break;
	case SPDK_FSDEV_UNLCK:
		fuse_lock->type = fsdev_io_h2d_u32(fuse_io->disp, F_UNLCK);
		break;
	default:
		SPDK_ERRLOG("Invalid lock type %d encountered during fsdev to fuse "
			    "locks conversion.\n", fsdev_lock->type);
		return -EINVAL;
	}

	fuse_lock->start = fsdev_io_h2d_u64(fuse_io->disp, fsdev_lock->start);
	fuse_lock->end = fsdev_io_h2d_u64(fuse_io->disp, fsdev_lock->end);
	fuse_lock->pid = fsdev_io_h2d_u32(fuse_io->disp, fsdev_lock->pid);

	SPDK_DEBUGLOG(fuse_dispatcher, "fsdev -> fuse lock type=%s, start=%lu, len=%lu, pid=%u\n",
		      fuse_lock_type_to_str(fsdev_io_d2h_u32(fuse_io->disp, fsdev_lock->type)),
		      fuse_lock->start, fuse_lock->end, fuse_lock->pid);
	return 0;
}

static void
fuse_dispatcher_io_complete_getlk(struct fuse_io *fuse_io,
				  const struct spdk_fsdev_file_lock *fsdev_lock)
{
	struct fuse_lk_out *arg;
	int err;

	arg = _fsdev_io_out_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_lk_out\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = fsdev_file_lock_to_fuse(fuse_io, fsdev_lock, &arg->lk);
	if (!err) {
		fuse_dispatcher_io_complete_ok(fuse_io, sizeof(*arg));
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

/* `buf` is allowed to be empty so that the proper size may be
   allocated by the caller */
static size_t
fuse_dispatcher_add_direntry(struct fuse_io *fuse_io, char *buf, size_t bufsize,
			     const char *name, struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr,
			     off_t off)
{
	size_t namelen;
	size_t entlen;
	size_t entlen_padded;
	struct fuse_dirent *dirent;

	namelen = strlen(name);
	entlen = FUSE_NAME_OFFSET + namelen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);

	if ((buf == NULL) || (entlen_padded > bufsize)) {
		return entlen_padded;
	}

	dirent = (struct fuse_dirent *) buf;
	dirent->ino = file_ino(fuse_io->disp, fobject);
	dirent->off = fsdev_io_h2d_u64(fuse_io->disp, off);
	dirent->namelen = fsdev_io_h2d_u32(fuse_io->disp, namelen);
	dirent->type = fsdev_io_h2d_u32(fuse_io->disp, (attr->mode & 0170000) >> 12);
	memcpy(dirent->name, name, namelen);
	memset(dirent->name + namelen, 0, entlen_padded - entlen);

	return entlen_padded;
}

/* `buf` is allowed to be empty so that the proper size may be
   allocated by the caller */
static size_t
fuse_dispatcher_add_direntry_plus(struct fuse_io *fuse_io, char *buf, size_t bufsize,
				  const char *name, struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr,
				  off_t off)
{
	size_t namelen;
	size_t entlen;
	size_t entlen_padded;

	namelen = strlen(name);
	entlen = FUSE_NAME_OFFSET_DIRENTPLUS + namelen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if ((buf == NULL) || (entlen_padded > bufsize)) {
		return entlen_padded;
	}

	struct fuse_direntplus *dp = (struct fuse_direntplus *) buf;
	memset(&dp->entry_out, 0, sizeof(dp->entry_out));
	fill_entry(fuse_io, &dp->entry_out, fobject, attr);

	struct fuse_dirent *dirent = &dp->dirent;
	dirent->ino = fsdev_io_h2d_u64(fuse_io->disp, attr->ino);
	dirent->off = fsdev_io_h2d_u64(fuse_io->disp, off);
	dirent->namelen = fsdev_io_h2d_u32(fuse_io->disp, namelen);
	dirent->type = fsdev_io_h2d_u32(fuse_io->disp, (attr->mode & 0170000) >> 12);
	memcpy(dirent->name, name, namelen);
	memset(dirent->name + namelen, 0, entlen_padded - entlen);

	return entlen_padded;
}

/*
 * Static FUSE commands handlers
 */
static inline struct spdk_fsdev_desc *
fuse_io_desc(struct fuse_io *fuse_io)
{
	return fuse_io->disp->desc;
}

static void
do_lookup_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		  struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_entry(fuse_io, fobject, attr);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_lookup(struct fuse_io *fuse_io)
{
	int err;
	const char *name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("No name or bad name attached\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_lookup(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				file_object(fuse_io), name, do_lookup_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_forget_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_none(fuse_io, status); /* FUSE_FORGET requires no response */
}

static void
do_forget(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_forget_in *arg;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_forget_in\n");
		fuse_dispatcher_io_complete_none(fuse_io, -EINVAL); /* FUSE_FORGET requires no response */
		return;
	}

	err = spdk_fsdev_forget(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				file_object(fuse_io), fsdev_io_d2h_u64(fuse_io->disp, arg->nlookup),
				do_forget_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_getattr_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		   const struct spdk_fsdev_file_attr *attr)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_attr(fuse_io, attr);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_getattr(struct fuse_io *fuse_io)
{
	int err;
	uint64_t fh = 0;

	if (fsdev_io_proto_minor(fuse_io) >= 9) {
		struct fuse_getattr_in *arg;

		arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
		if (!arg) {
			SPDK_ERRLOG("Cannot get fuse_getattr_in\n");
			fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
			return;
		}

		if (fsdev_io_d2h_u64(fuse_io->disp, arg->getattr_flags) & FUSE_GETATTR_FH) {
			fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
		}
	}

	err = spdk_fsdev_getattr(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				 file_object(fuse_io), file_handle(fh), do_getattr_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

#define FATTR_FLAGS_MAP \
	FATTR_FLAG(ATTR_MODE)       \
	FATTR_FLAG(ATTR_UID)        \
	FATTR_FLAG(ATTR_GID)        \
	FATTR_FLAG(ATTR_SIZE)       \
	FATTR_FLAG(ATTR_ATIME)      \
	FATTR_FLAG(ATTR_MTIME)      \
	FATTR_FLAG(ATTR_ATIME_NOW)  \
	FATTR_FLAG(ATTR_MTIME_NOW)  \
	FATTR_FLAG(ATTR_CTIME)

static uint32_t
fuse_fattr_flags_to_fsdev(uint32_t flags)
{
	uint32_t result = 0;

#define FATTR_FLAG(name) \
	if (flags & F##name) {               \
		result |= SPDK_FSDEV_##name; \
	}

	FATTR_FLAGS_MAP;

#undef FXATTR_FLAG

	return result;
}

static void
do_setattr_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		   const struct spdk_fsdev_file_attr *attr)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_attr(fuse_io, attr);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_setattr(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_setattr_in *arg;
	uint32_t valid;
	uint64_t fh = 0;
	struct spdk_fsdev_file_attr attr;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_setattr_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	memset(&attr, 0, sizeof(attr));
	attr.mode      = fsdev_io_d2h_u32(fuse_io->disp, arg->mode);
	attr.uid       = fsdev_io_d2h_u32(fuse_io->disp, arg->uid);
	attr.gid       = fsdev_io_d2h_u32(fuse_io->disp, arg->gid);
	attr.size      = fsdev_io_d2h_u64(fuse_io->disp, arg->size);
	attr.atime     = fsdev_io_d2h_u64(fuse_io->disp, arg->atime);
	attr.mtime     = fsdev_io_d2h_u64(fuse_io->disp, arg->mtime);
	attr.ctime     = fsdev_io_d2h_u64(fuse_io->disp, arg->ctime);
	attr.atimensec = fsdev_io_d2h_u32(fuse_io->disp, arg->atimensec);
	attr.mtimensec = fsdev_io_d2h_u32(fuse_io->disp, arg->mtimensec);
	attr.ctimensec = fsdev_io_d2h_u32(fuse_io->disp, arg->ctimensec);

	valid = fsdev_io_d2h_u64(fuse_io->disp, arg->valid);
	if (valid & FATTR_FH) {
		valid &= ~FATTR_FH;
		fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
	}
	valid = fuse_fattr_flags_to_fsdev(valid);

	valid &=
		SPDK_FSDEV_ATTR_MODE |
		SPDK_FSDEV_ATTR_UID |
		SPDK_FSDEV_ATTR_GID |
		SPDK_FSDEV_ATTR_SIZE |
		SPDK_FSDEV_ATTR_ATIME |
		SPDK_FSDEV_ATTR_MTIME |
		SPDK_FSDEV_ATTR_ATIME_NOW |
		SPDK_FSDEV_ATTR_MTIME_NOW |
		SPDK_FSDEV_ATTR_CTIME;

	err = spdk_fsdev_setattr(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				 file_object(fuse_io), file_handle(fh), &attr, valid,
				 do_setattr_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_readlink_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status, const char *linkname)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_copy_and_complete(fuse_io, linkname, strlen(linkname) + 1, 0);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_readlink(struct fuse_io *fuse_io)
{
	int err;

	err = spdk_fsdev_readlink(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				  file_object(fuse_io), do_readlink_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_symlink_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		   struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_entry(fuse_io, fobject, attr);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_symlink(struct fuse_io *fuse_io)
{
	int err;
	const char *name, *linkname;

	name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("Cannot get name\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	linkname = _fsdev_io_in_arg_get_str(fuse_io);
	if (!linkname) {
		SPDK_ERRLOG("Cannot get linkname\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_symlink(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				 file_object(fuse_io), name, linkname, fuse_io->hdr.uid, fuse_io->hdr.gid,
				 do_symlink_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_mknod_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		 struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_entry(fuse_io, fobject, attr);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_mknod(struct fuse_io *fuse_io)
{
	int err;
	bool compat = fsdev_io_proto_minor(fuse_io) < 12;
	struct fuse_mknod_in *arg;
	const char *name;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, compat ? FUSE_COMPAT_MKNOD_IN_SIZE : sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_mknod_in (compat=%d)\n", compat);
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("Cannot get name (compat=%d)\n", compat);
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_mknod(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), name, fsdev_io_d2h_u32(fuse_io->disp, arg->mode),
			       fsdev_io_d2h_u32(fuse_io->disp, arg->rdev), fsdev_io_d2h_u32(fuse_io->disp, arg->umask),
			       fuse_io->hdr.uid, fuse_io->hdr.gid, do_mknod_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_mkdir_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		 struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_entry(fuse_io, fobject, attr);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_mkdir(struct fuse_io *fuse_io)
{
	int err;
	bool compat = fsdev_io_proto_minor(fuse_io) < 12;
	struct fuse_mkdir_in *arg;
	const char *name;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, compat ? sizeof(uint32_t) : sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_mkdir_in (compat=%d)\n", compat);
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("Cannot get name (compat=%d)\n", compat);
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_mkdir(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), name, fsdev_io_d2h_u32(fuse_io->disp, arg->mode),
			       fsdev_io_d2h_u32(fuse_io->disp, arg->umask), fuse_io->hdr.uid, fuse_io->hdr.gid,
			       do_mkdir_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_unlink_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_unlink(struct fuse_io *fuse_io)
{
	int err;
	const char *name;

	name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("Cannot get name\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_unlink(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				file_object(fuse_io), name, do_unlink_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_rmdir_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_rmdir(struct fuse_io *fuse_io)
{
	int err;
	const char *name;

	name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("Cannot get name\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_rmdir(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), name, do_rmdir_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

#define RENAME2_FLAGS_MAP \
	RENAME2_FLAG(EXCHANGE)  \
	RENAME2_FLAG(NOREPLACE) \
	RENAME2_FLAG(WHITEOUT)

static uint32_t
fuse_rename2_flags_to_fsdev(uint32_t flags)
{
	uint32_t result = 0;

#define RENAME2_FLAG(name) \
	if (flags & RENAME_##name) {                \
		result |= SPDK_FSDEV_RENAME_##name; \
	}

	RENAME2_FLAGS_MAP;

#undef RENAME2_FLAG

	return result;
}

static void
do_rename_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_rename_common(struct fuse_io *fuse_io, bool version2)
{
	int err;
	uint64_t newdir;
	const char *oldname;
	const char *newname;
	uint32_t flags = 0;

	if (!version2) {
		struct fuse_rename_in *arg;
		arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
		if (!arg) {
			SPDK_ERRLOG("Cannot get fuse_rename_in\n");
			fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
			return;
		}
		newdir = fsdev_io_d2h_u64(fuse_io->disp, arg->newdir);
	} else {
		struct fuse_rename2_in *arg;
		arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
		if (!arg) {
			SPDK_ERRLOG("Cannot get fuse_rename2_in\n");
			fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
			return;
		}
		newdir = fsdev_io_d2h_u64(fuse_io->disp, arg->newdir);
		flags = fsdev_io_d2h_u64(fuse_io->disp, arg->flags);
		flags = fuse_rename2_flags_to_fsdev(flags);
	}

	oldname = _fsdev_io_in_arg_get_str(fuse_io);
	if (!oldname) {
		SPDK_ERRLOG("Cannot get oldname\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	newname = _fsdev_io_in_arg_get_str(fuse_io);
	if (!newname) {
		SPDK_ERRLOG("Cannot get newname\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_rename(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				file_object(fuse_io), oldname, ino_to_object(fuse_io, newdir),
				newname, flags, do_rename_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_rename(struct fuse_io *fuse_io)
{
	do_rename_common(fuse_io, false);
}

static void
do_rename2(struct fuse_io *fuse_io)
{
	do_rename_common(fuse_io, true);
}

static void
do_link_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_entry(fuse_io, fobject, attr);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_link(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_link_in *arg;
	const char *name;
	uint64_t oldnodeid;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_link_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("Cannot get name\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	oldnodeid = fsdev_io_d2h_u64(fuse_io->disp, arg->oldnodeid);

	err = spdk_fsdev_link(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			      ino_to_object(fuse_io, oldnodeid), file_object(fuse_io), name,
			      do_link_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_fopen_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		 struct spdk_fsdev_file_handle *fhandle)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_open(fuse_io, fhandle);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_open(struct fuse_io *fuse_io)
{
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;
	int err;
	struct fuse_open_in *arg;
	uint32_t flags;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_forget_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	if (!fsdev_d2h_open_flags(disp->fuse_arch, fsdev_io_d2h_u32(fuse_io->disp, arg->flags), &flags)) {
		SPDK_ERRLOG("Cannot translate flags\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_fopen(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), flags,
			       do_fopen_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_read_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status, uint32_t data_size)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete(fuse_io, data_size, status);
}

static void
do_read(struct fuse_io *fuse_io)
{
	int err;
	bool compat = fsdev_io_proto_minor(fuse_io) < 9;
	struct fuse_read_in *arg;
	uint64_t fh;
	uint32_t flags = 0;

	arg = _fsdev_io_in_arg_get_buf(fuse_io,
				       compat ? offsetof(struct fuse_read_in, lock_owner) : sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_read_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}


	if (!compat) {
		flags = fsdev_io_d2h_u32(fuse_io->disp, arg->flags);
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);

	err = spdk_fsdev_read(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			      file_object(fuse_io), file_handle(fh),
			      fsdev_io_d2h_u32(fuse_io->disp, arg->size), fsdev_io_d2h_u64(fuse_io->disp, arg->offset),
			      flags, fuse_io->out_iov + 1, fuse_io->out_iovcnt - 1, NULL,
			      do_read_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_write_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status, uint32_t data_size)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_write(fuse_io, data_size, status);
}

static void
do_write(struct fuse_io *fuse_io)
{
	int err;
	bool compat = fsdev_io_proto_minor(fuse_io) < 9;
	struct fuse_write_in *arg;
	uint64_t fh;
	uint64_t flags = 0;

	arg = _fsdev_io_in_arg_get_buf(fuse_io,
				       compat ? FUSE_COMPAT_WRITE_IN_SIZE : sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_write_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	if (fuse_io->in_offs.buf_offs) {
		SPDK_ERRLOG("Data IOVs should be separate from the header IOV\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	if (!compat) {
		flags = fsdev_io_d2h_u32(fuse_io->disp, arg->flags);
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);

	err = spdk_fsdev_write(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), file_handle(fh),
			       fsdev_io_d2h_u32(fuse_io->disp, arg->size), fsdev_io_d2h_u64(fuse_io->disp, arg->offset),
			       flags, fuse_io->in_iov + fuse_io->in_offs.iov_offs, fuse_io->in_iovcnt - fuse_io->in_offs.iov_offs,
			       NULL, do_write_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_statfs_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		  const struct spdk_fsdev_file_statfs *statfs)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_statfs(fuse_io, statfs);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_statfs(struct fuse_io *fuse_io)
{
	int err;

	err = spdk_fsdev_statfs(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				file_object(fuse_io), do_statfs_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_release_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_release(struct fuse_io *fuse_io)
{
	int err;
	bool compat = fsdev_io_proto_minor(fuse_io) < 8;
	struct fuse_release_in *arg;
	uint64_t fh;

	arg = _fsdev_io_in_arg_get_buf(fuse_io,
				       compat ? offsetof(struct fuse_release_in, lock_owner) : sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_release_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);

	err = spdk_fsdev_release(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				 file_object(fuse_io), file_handle(fh),
				 do_release_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_fsync_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_fsync(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_fsync_in *arg;
	uint64_t fh;
	bool datasync;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_fsync_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
	datasync = (fsdev_io_d2h_u32(fuse_io->disp, arg->fsync_flags) & 1) ? true : false;

	err = spdk_fsdev_fsync(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), file_handle(fh), datasync,
			       do_fsync_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

#define XATTR_FLAGS_MAP \
	XATTR_FLAG(XATTR_CREATE) \
	XATTR_FLAG(XATTR_REPLACE)

static uint64_t
fuse_xattr_flags_to_fsdev(uint32_t flags)
{
	uint64_t result = 0;

#define XATTR_FLAG(name) \
	if (flags & name) {                  \
		result |= SPDK_FSDEV_##name; \
	}

	XATTR_FLAGS_MAP;

#undef XATTR_FLAG

	return result;
}

#define XATTR_EXT_FLAGS_MAP \
	XATTR_EXT_FLAG(SETXATTR_ACL_KILL_SGID)

static uint64_t
fuse_xattr_ext_flags_to_fsdev(uint32_t flags)
{
	uint64_t result = 0;

#define XATTR_EXT_FLAG(name) \
	if (flags & FUSE_##name) {           \
		result |= SPDK_FSDEV_##name; \
	}

	XATTR_EXT_FLAGS_MAP;

#undef XATTR_EXT_FLAG

	return result;
}

static void
do_setxattr_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_setxattr(struct fuse_io *fuse_io)
{
	int err;
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;
	bool xattr_ext = !!(disp->mount_flags & FUSE_SETXATTR_EXT);
	struct fuse_setxattr_in *arg;
	const char *name;
	const char *value;
	uint32_t size;
	uint64_t flags;

	size = xattr_ext ? sizeof(*arg) : FUSE_COMPAT_SETXATTR_IN_SIZE;
	arg = _fsdev_io_in_arg_get_buf(fuse_io, size);
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_setxattr_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("Cannot get name\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	size = fsdev_io_d2h_u32(fuse_io->disp, arg->size);
	value = _fsdev_io_in_arg_get_buf(fuse_io, size);
	if (!value) {
		SPDK_ERRLOG("Cannot get value of %" PRIu32 " bytes\n", size);
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	flags = fuse_xattr_flags_to_fsdev(fsdev_io_d2h_u32(fuse_io->disp, arg->flags));
	if (xattr_ext) {
		flags |= fuse_xattr_ext_flags_to_fsdev(fsdev_io_d2h_u32(fuse_io->disp, arg->setxattr_flags));
	}

	err = spdk_fsdev_setxattr(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				  file_object(fuse_io), name, value, size, flags,
				  do_setxattr_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_getxattr_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status, size_t value_size)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_xattr(fuse_io, value_size);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_getxattr(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_getxattr_in *arg;
	const char *name;
	char *buff = NULL;
	uint32_t size;
	struct iov_offs out_offs_bu;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_getxattr_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("Cannot get name\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	if (fuse_io->out_iovcnt < 2) {
		SPDK_ERRLOG("No buffer to getxattr\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	size = fsdev_io_d2h_u32(fuse_io->disp, arg->size);

	/* Zero size means requesting size of the xattr value. No need to go further. */
	if (size > 0) {
		/*
		 * NOTE: we want to avoid an additionl allocation and copy and put the xattr
		 * directly to the buffer provided in out_iov. In order to do so we have to
		 * preserve the out_offs, advance it to get the buffer pointer and then restore
		 * to allow the fuse_dispatcher_io_complete_xattr() to fill the fuse_getxattr_out
		 * which precedes this buffer.
		 */
		out_offs_bu = fuse_io->out_offs; /* Preserve the out offset */

		/* Skip the fuse_getxattr_out */
		_fsdev_io_out_arg_get_buf(fuse_io, sizeof(struct fuse_getxattr_out));
		if (size < sizeof(struct fuse_getxattr_out)) {
			SPDK_ERRLOG("Invalid size=%u smaller than the size of fuse_getxattr_out=%lu "
				    "in getxattr request.\n", size, sizeof(struct fuse_getxattr_out));
			fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
			return;
		}
		size -= sizeof(struct fuse_getxattr_out);

		buff = _fsdev_io_out_arg_get_buf(fuse_io, size); /* Get the buffer for the xattr */
		if (!buff) {
			/*
			 * Should not happen at this point but let's ignore it. Null buff and zere
			 * size are valid inputs for spdk_fsdev_getxattr().
			 */
			size = 0;
		}
		fuse_io->out_offs = out_offs_bu; /* Restore the out offset */
	}

	err = spdk_fsdev_getxattr(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				  file_object(fuse_io), name, buff, size,
				  do_getxattr_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_listxattr_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status, size_t size,
		     bool size_only)
{
	struct fuse_io *fuse_io = cb_arg;

	if (status) {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	} else if (size_only) {
		fuse_dispatcher_io_complete_xattr(fuse_io, size);
	} else {
		fuse_dispatcher_io_complete_ok(fuse_io, size);
	}
}

static void
do_listxattr(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_getxattr_in *arg;
	struct iovec *iov;
	uint32_t size;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_getxattr_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	size = fsdev_io_d2h_u32(fuse_io->disp, arg->size);
	iov = fuse_io->out_iov + 1;
	if (iov->iov_len < size) {
		SPDK_ERRLOG("Wrong iov len (%zu < %" PRIu32")\n", iov->iov_len, size);
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_listxattr(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				   file_object(fuse_io), iov->iov_base, size,
				   do_listxattr_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_removexattr_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_removexattr(struct fuse_io *fuse_io)
{
	int err;
	const char *name = _fsdev_io_in_arg_get_str(fuse_io);

	if (!name) {
		SPDK_ERRLOG("Cannot get name\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_removexattr(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				     file_object(fuse_io), name, do_removexattr_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_flush_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_flush(struct fuse_io *fuse_io)
{
	int err;
	bool compat = fsdev_io_proto_minor(fuse_io) < 7;
	struct fuse_flush_in *arg;
	uint64_t fh;

	arg = _fsdev_io_in_arg_get_buf(fuse_io,
				       compat ? offsetof(struct fuse_flush_in, lock_owner) : sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_flush_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);

	err = spdk_fsdev_flush(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), file_handle(fh),
			       do_flush_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_mount_rollback_cpl_clb(void *cb_arg, struct spdk_io_channel *ch)
{
	struct fuse_io *fuse_io = cb_arg;
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;

	UNUSED(disp);

	SPDK_DEBUGLOG(fuse_dispatcher, "%s unmounted\n", fuse_dispatcher_name(disp));

	/* The IO is FUSE_INIT, so we complete it with the appropriate error */
	fuse_dispatcher_io_complete_err(fuse_io, fuse_io->u.init.error);
}

static void fuse_dispatcher_mount_rollback_msg(void *ctx);

static void
fuse_dispatcher_mount_rollback(struct fuse_io *fuse_io)
{
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;
	int rc;

	rc = spdk_fsdev_umount(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       do_mount_rollback_cpl_clb, fuse_io);
	if (rc) {
		/* It can only fail due to a lack of the IO objects, so we retry until one of them will be available */
		SPDK_WARNLOG("%s: umount cannot be initiated (err=%d). Retrying...\n",
			     fuse_dispatcher_name(disp), rc);
		spdk_thread_send_msg(spdk_get_thread(), fuse_dispatcher_mount_rollback_msg, fuse_io);
	}
}

static void
fuse_dispatcher_mount_rollback_msg(void *ctx)
{
	struct fuse_io *fuse_io = ctx;

	fuse_dispatcher_mount_rollback(fuse_io);
}

#define FUSE_DOT_PATH_LOOKUP FUSE_EXPORT_SUPPORT

#define MNT_FLAGS_MAP \
	MNT_FLAG(DOT_PATH_LOOKUP)      \
	MNT_FLAG(AUTO_INVAL_DATA)      \
	MNT_FLAG(EXPLICIT_INVAL_DATA)  \
	MNT_FLAG(WRITEBACK_CACHE)      \
	MNT_FLAG(POSIX_ACL)

static uint32_t
fuse_mount_flags_to_fsdev(uint32_t flags)
{
	uint64_t result = 0;


#define MNT_FLAG(name) \
	if (flags & FUSE_##name) {                 \
		result |= SPDK_FSDEV_MOUNT_##name; \
	}

	MNT_FLAGS_MAP;

#undef MNT_FLAG

	return result;
}

static uint32_t
fsdev_mount_flags_to_fuse(uint32_t flags)
{
	uint32_t result = 0;

#define MNT_FLAG(name) \
	if (flags & SPDK_FSDEV_MOUNT_##name) { \
		result |= FUSE_##name;   \
	}

	MNT_FLAGS_MAP;

#undef MNT_FLAG

	return result;
}

#define SET_MOUNT_FLAG(cond, stage, flag) \
	if ((cond) && (requested_flags & (FUSE_##flag))) { \
		stage |= (FUSE_##flag);			   \
	}

/* Maximal number of pages for unlimited max_xfer_size. Using FUSE page limit value. */
#define SPDK_FSDEV_PAGE_LIMIT 256

static int
do_mount_prepare_completion(struct fuse_io *fuse_io,
			    const struct spdk_fsdev_mount_opts *negotiated_opts)
{
	uint32_t requested_flags = fsdev_io_d2h_u32(fuse_io->disp, fuse_io->u.init.in->flags);
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;
	struct fuse_init_out outarg;
	size_t outargsize = sizeof(outarg);
	uint32_t supported = 0;
	uint32_t max_xfer_size;
	void *out_buf;

	assert(disp->desc);

	memset(&outarg, 0, sizeof(outarg));
	outarg.major = fsdev_io_h2d_u32(fuse_io->disp, FUSE_KERNEL_VERSION);
	outarg.minor = fsdev_io_h2d_u32(fuse_io->disp, FUSE_KERNEL_MINOR_VERSION);

	if (disp->proto_minor < 5) {
		outargsize = FUSE_COMPAT_INIT_OUT_SIZE;
	} else if (disp->proto_minor < 23) {
		outargsize = FUSE_COMPAT_22_INIT_OUT_SIZE;
	}

	/* Always supported if requested by the FUSE. */
	SET_MOUNT_FLAG(true, supported, ASYNC_READ);
	SET_MOUNT_FLAG(true, supported, ATOMIC_O_TRUNC);
	SET_MOUNT_FLAG(true, supported, BIG_WRITES);
	SET_MOUNT_FLAG(true, supported, DONT_MASK);
	SET_MOUNT_FLAG(true, supported, DO_READDIRPLUS);
	SET_MOUNT_FLAG(true, supported, READDIRPLUS_AUTO);
	SET_MOUNT_FLAG(true, supported, ASYNC_DIO);
	SET_MOUNT_FLAG(true, supported, NO_OPEN_SUPPORT);
	SET_MOUNT_FLAG(true, supported, PARALLEL_DIROPS);
	SET_MOUNT_FLAG(true, supported, HANDLE_KILLPRIV);
	SET_MOUNT_FLAG(true, supported, CACHE_SYMLINKS);
	SET_MOUNT_FLAG(true, supported, NO_OPENDIR_SUPPORT);
	SET_MOUNT_FLAG(true, supported, SUBMOUNTS);
	SET_MOUNT_FLAG(true, supported, HANDLE_KILLPRIV_V2);
	SET_MOUNT_FLAG(true, supported, MAX_PAGES);

	SET_MOUNT_FLAG(true, supported, POSIX_LOCKS);
	SET_MOUNT_FLAG(true, supported, SETXATTR_EXT);
	SET_MOUNT_FLAG(true, supported, FLOCK_LOCKS);
	SET_MOUNT_FLAG(true, supported, HAS_IOCTL_DIR);

	/* Sending back the fsdev negotiated mount opts. */
	supported |= fsdev_mount_flags_to_fuse(negotiated_opts->flags);
	outarg.flags = fsdev_io_h2d_u32(fuse_io->disp, supported);
	disp->mount_flags = supported;

	outarg.max_readahead = fsdev_io_h2d_u32(fuse_io->disp, negotiated_opts->max_readahead);

	max_xfer_size = negotiated_opts->max_xfer_size;

	if (max_xfer_size == 0) {
		/*
		 * The number of pages used by FUSE (and controlled when parsing max_pages) is
		 * limited to 256 pags. Let's use this value for unlimited case.
		 */
		max_xfer_size = SPDK_FSDEV_PAGE_LIMIT * PAGE_SIZE;
		SPDK_WARNLOG("FSDEV reported max_xfer_size = 0 (unlimited). Setting max_xfer_size = %u.\n",
			     max_xfer_size);
	}

	/*
	 * If max_xfer_size returned from the fsdev is <= 4k and we send max_write of
	 * this value to the FUSE it will set its own default = 4k as for today.
	 */
	outarg.max_write = fsdev_io_h2d_u32(fuse_io->disp, max_xfer_size);

	/*
	 * Sending max_pages == 0 to the FUSE will result into setting it to default
	 * value == 1.
	 */
	outarg.max_pages = max_xfer_size / PAGE_SIZE;
	outarg.max_pages = fsdev_io_h2d_u32(fuse_io->disp, outarg.max_pages);

	if (fsdev_io_proto_minor(fuse_io) >= 13) {
		outarg.max_background = fsdev_io_h2d_u16(fuse_io->disp, DEFAULT_MAX_BACKGROUND);
		outarg.congestion_threshold = fsdev_io_h2d_u16(fuse_io->disp, DEFAULT_CONGESTION_THRESHOLD);
	}

	if (fsdev_io_proto_minor(fuse_io) >= 23) {
		outarg.time_gran = fsdev_io_h2d_u32(fuse_io->disp, DEFAULT_TIME_GRAN);
	}

	SPDK_INFOLOG(fuse_dispatcher, "INIT: %" PRIu32 ".%" PRIu32 "\n",
		     fsdev_io_d2h_u32(fuse_io->disp, outarg.major), fsdev_io_d2h_u32(fuse_io->disp, outarg.minor));
	SPDK_INFOLOG(fuse_dispatcher, "mount_flags: 0x%08" PRIx32 "\n",
		     fsdev_io_h2d_u32(fuse_io->disp, fsdev_mount_flags_to_fuse(supported)));
	SPDK_INFOLOG(fuse_dispatcher, "max_readahead: %" PRIu32 "\n",
		     fsdev_io_d2h_u32(fuse_io->disp, outarg.max_readahead));
	SPDK_INFOLOG(fuse_dispatcher, "max_write: %" PRIu32 "\n",
		     fsdev_io_d2h_u32(fuse_io->disp, outarg.max_write));
	SPDK_INFOLOG(fuse_dispatcher, "max_pages: %" PRIu32 "\n",
		     fsdev_io_d2h_u32(fuse_io->disp, outarg.max_pages));
	SPDK_INFOLOG(fuse_dispatcher, "max_background: %" PRIu16 "\n",
		     fsdev_io_d2h_u16(fuse_io->disp, outarg.max_background));
	SPDK_INFOLOG(fuse_dispatcher, "congestion_threshold: %" PRIu16 "\n",
		     fsdev_io_d2h_u16(fuse_io->disp, outarg.congestion_threshold));
	SPDK_INFOLOG(fuse_dispatcher, "time_gran: %" PRIu32 "\n", fsdev_io_d2h_u32(fuse_io->disp,
			outarg.time_gran));

	out_buf = _fsdev_io_out_arg_get_buf(fuse_io, outargsize);
	if (!out_buf) {
		SPDK_ERRLOG("Cannot get buf to copy fuse_init_out of %zu bytes\n", outargsize);
		return -EINVAL;
	}

	memcpy(out_buf, &outarg, outargsize);

	fuse_io->u.init.out_len = outargsize;
	return 0;
}

static void
do_mount_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		 const struct spdk_fsdev_mount_opts *opts, struct spdk_fsdev_file_object *root_fobject)
{
	struct fuse_io *fuse_io = cb_arg;
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;
	int rc;

	if (status) {
		SPDK_ERRLOG("%s: spdk_fsdev_mount failed (err=%d)\n", fuse_dispatcher_name(disp), status);
		fuse_dispatcher_io_complete_err(fuse_io, status);
		return;
	}

	SPDK_DEBUGLOG(fuse_dispatcher, "%s: spdk_fsdev_mount succeeded\n", fuse_dispatcher_name(disp));
	disp->root_fobject = root_fobject;
	rc = do_mount_prepare_completion(fuse_io, opts);
	if (rc) {
		SPDK_ERRLOG("%s: mount completion preparation failed with %d\n", fuse_dispatcher_name(disp), rc);
		fuse_io->u.init.error = rc;
		disp->root_fobject = NULL;
		fuse_dispatcher_mount_rollback(fuse_io);
		return;
	}

	/* Save the negotiated state */
	fuse_dispatcher_update_rmem(disp);

	fuse_dispatcher_io_complete_ok(fuse_io, fuse_io->u.init.out_len);
}

static void
do_init(struct fuse_io *fuse_io)
{
	size_t compat_size = offsetof(struct fuse_init_in, max_readahead);
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;
	uint32_t max_readahead = DEFAULT_MAX_READAHEAD;
	uint32_t requested_flags = 0;
	uint32_t flags = 0;
	int rc;

	/* First try to read the legacy header */
	fuse_io->u.init.in = _fsdev_io_in_arg_get_buf(fuse_io, compat_size);
	if (!fuse_io->u.init.in) {
		SPDK_ERRLOG("Cannot get fuse_init_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EBADR);
		return;
	}

	disp->proto_major = fsdev_io_d2h_u32(fuse_io->disp, fuse_io->u.init.in->major);
	disp->proto_minor = fsdev_io_d2h_u32(fuse_io->disp, fuse_io->u.init.in->minor);

	SPDK_DEBUGLOG(fuse_dispatcher, "Proto version: %" PRIu32 ".%" PRIu32 "\n",
		      disp->proto_major,
		      disp->proto_minor);

	/* Now try to read the whole struct */
	if (disp->proto_major == 7 && disp->proto_minor >= 6) {
		void *arg_extra = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*fuse_io->u.init.in) - compat_size);
		if (!arg_extra) {
			SPDK_ERRLOG("INIT: protocol version: %" PRIu32 ".%" PRIu32 " but legacy data found\n",
				    disp->proto_major, disp->proto_minor);
			fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
			return;
		}
		fuse_io->u.init.legacy_in = false;
	} else {
		fuse_io->u.init.legacy_in = true;
	}

	if (disp->proto_major < 7) {
		SPDK_ERRLOG("INIT: unsupported major protocol version: %" PRIu32 "\n",
			    disp->proto_major);
		fuse_dispatcher_io_complete_err(fuse_io, -EAGAIN);
		return;
	}

	if (disp->proto_major > 7) {
		/* Wait for a second INIT request with a 7.X version */

		struct fuse_init_out outarg;
		size_t outargsize = sizeof(outarg);

		memset(&outarg, 0, sizeof(outarg));
		outarg.major = fsdev_io_h2d_u32(fuse_io->disp, FUSE_KERNEL_VERSION);
		outarg.minor = fsdev_io_h2d_u32(fuse_io->disp, FUSE_KERNEL_MINOR_VERSION);

		fuse_dispatcher_io_copy_and_complete(fuse_io, &outarg, outargsize, 0);
		return;
	}

	if (!fuse_io->u.init.legacy_in) {
		requested_flags = fsdev_io_d2h_u32(fuse_io->disp, fuse_io->u.init.in->flags);
		max_readahead = fsdev_io_d2h_u32(fuse_io->disp, fuse_io->u.init.in->max_readahead);
		SPDK_INFOLOG(fuse_dispatcher, "requested: flags=0x%" PRIx32 " max_readahead=%" PRIu32 "\n",
			     requested_flags, max_readahead);
	}

	/* Negotiate the following options if requested by the FUSE. */
	SET_MOUNT_FLAG(true, flags, DOT_PATH_LOOKUP);
	SET_MOUNT_FLAG(true, flags, AUTO_INVAL_DATA);
	SET_MOUNT_FLAG(true, flags, EXPLICIT_INVAL_DATA);
	SET_MOUNT_FLAG(true, flags, WRITEBACK_CACHE);
	SET_MOUNT_FLAG(true, flags, POSIX_ACL);

	memset(&fuse_io->u.init.opts, 0, sizeof(fuse_io->u.init.opts));
	fuse_io->u.init.opts.opts_size = sizeof(fuse_io->u.init.opts);

	/* Passing for negotiation only few flags. The rest are always supported. */
	fuse_io->u.init.opts.flags = fuse_mount_flags_to_fsdev(flags);
	fuse_io->u.init.opts.max_readahead = max_readahead;
	fuse_io->u.init.thread = spdk_get_thread();

	rc = spdk_fsdev_mount(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			      &fuse_io->u.init.opts, do_mount_cpl_clb, fuse_io);
	if (rc) {
		SPDK_ERRLOG("%s: failed to initiate mount (err=%d)\n", fuse_dispatcher_name(disp), rc);
		fuse_dispatcher_io_complete_err(fuse_io, rc);
	}
}

#undef SET_MOUNT_FLAG

static void
do_opendir_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		   struct spdk_fsdev_file_handle *fhandle)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_open(fuse_io, fhandle);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_opendir(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_open_in *arg;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_open_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_opendir(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				 file_object(fuse_io), fsdev_io_d2h_u32(fuse_io->disp, arg->flags),
				 do_opendir_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static int
do_readdir_entry_clb(void *cb_arg, struct spdk_io_channel *ch, const char *name,
		     struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr,
		     off_t offset, bool *forget)
{
	struct fuse_io *fuse_io = cb_arg;
	size_t bytes_remained = fuse_io->u.readdir.size - fuse_io->u.readdir.bytes_written;
	size_t direntry_bytes;

	direntry_bytes = fuse_io->u.readdir.plus ?
			 fuse_dispatcher_add_direntry_plus(fuse_io, fuse_io->u.readdir.writep, bytes_remained,
					 name, fobject, attr, offset) :
			 fuse_dispatcher_add_direntry(fuse_io, fuse_io->u.readdir.writep, bytes_remained,
					 name, fobject, attr, offset);

	if (direntry_bytes > bytes_remained) {
		return EAGAIN;
	}

	fuse_io->u.readdir.writep += direntry_bytes;
	fuse_io->u.readdir.bytes_written += direntry_bytes;

	*forget = fuse_io->u.readdir.plus ? false : true;

	return 0;
}

static void
do_readdir_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status || (status == EAGAIN && fuse_io->u.readdir.bytes_written == fuse_io->u.readdir.size)) {
		fuse_dispatcher_io_complete_ok(fuse_io, fuse_io->u.readdir.bytes_written);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_readdir_common(struct fuse_io *fuse_io, bool plus)
{
	int err;
	struct fuse_read_in *arg;
	uint64_t fh;
	uint32_t size;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_read_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	size = fsdev_io_d2h_u32(fuse_io->disp, arg->size);

	fuse_io->u.readdir.writep = _fsdev_io_out_arg_get_buf(fuse_io, size);
	if (!fuse_io->u.readdir.writep) {
		SPDK_ERRLOG("Cannot get buffer of %" PRIu32 " bytes\n", size);
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fuse_io->u.readdir.plus = plus;
	fuse_io->u.readdir.size = size;
	fuse_io->u.readdir.bytes_written = 0;

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);

	err = spdk_fsdev_readdir(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				 file_object(fuse_io), file_handle(fh),
				 fsdev_io_d2h_u64(fuse_io->disp, arg->offset),
				 do_readdir_entry_clb, do_readdir_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_readdir(struct fuse_io *fuse_io)
{
	do_readdir_common(fuse_io, false);
}

static void
do_readdirplus(struct fuse_io *fuse_io)
{
	do_readdir_common(fuse_io, true);
}

static void
do_releasedir_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_releasedir(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_release_in *arg;
	uint64_t fh;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_release_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);

	err = spdk_fsdev_releasedir(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				    file_object(fuse_io), file_handle(fh),
				    do_releasedir_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_fsyncdir_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_fsyncdir(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_fsync_in *arg;
	uint64_t fh;
	bool datasync;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_fsync_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
	datasync = (fsdev_io_d2h_u32(fuse_io->disp, arg->fsync_flags) & 1) ? true : false;

	err = spdk_fsdev_fsyncdir(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				  file_object(fuse_io), file_handle(fh), datasync,
				  do_fsyncdir_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_getlk_cpl_clb(void *cb_arg, struct spdk_io_channel *ch,
		 int status, const struct spdk_fsdev_file_lock *fsdev_lock)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_getlk(fuse_io, fsdev_lock);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_getlk(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_lk_in *arg;
	uint64_t fh;
	uint64_t owner;
	struct spdk_fsdev_file_lock fsdev_lock;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_lk_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
	owner = fsdev_io_d2h_u64(fuse_io->disp, arg->owner);

	err = fuse_to_fsdev_file_lock(fuse_io, &arg->lk, &fsdev_lock);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
		return;
	}

	err = spdk_fsdev_getlk(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), file_handle(fh), &fsdev_lock, owner,
			       do_getlk_cpl_clb, fuse_io);

	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_setlk_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_setlkw_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = (struct fuse_io *)cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_flock_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_setlk(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_lk_in *arg;
	uint64_t fh;
	struct spdk_fsdev_file_lock fsdev_lock;
	uint32_t lk_flags;
	uint64_t owner;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_lk_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
	owner = fsdev_io_d2h_u64(fuse_io->disp, arg->owner);
	lk_flags = fsdev_io_d2h_u32(fuse_io->disp, arg->lk_flags);

	/* Handling flock style of the lock. */
	if (lk_flags & FUSE_LK_FLOCK) {
		enum spdk_fsdev_file_lock_op op;

		switch (fsdev_io_d2h_u32(fuse_io->disp, arg->lk.type)) {
		case F_RDLCK:
			op = SPDK_FSDEV_LOCK_SH;
			break;
		case F_WRLCK:
			op = SPDK_FSDEV_LOCK_EX;
			break;
		case F_UNLCK:
			op = SPDK_FSDEV_LOCK_UN;
			break;
		default:
			SPDK_ERRLOG("Invalid lock type %d in fuse_lk_in\n",
				    fsdev_io_d2h_u32(fuse_io->disp, arg->lk.type));
			fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
			return;
		}

		err = spdk_fsdev_flock(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				       file_object(fuse_io), file_handle(fh), op,
				       do_flock_cpl_clb, fuse_io);
	} else {
		err = fuse_to_fsdev_file_lock(fuse_io, &arg->lk, &fsdev_lock);
		if (err) {
			fuse_dispatcher_io_complete_err(fuse_io, err);
			return;
		}
		err = spdk_fsdev_setlk(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				       file_object(fuse_io), file_handle(fh), &fsdev_lock, owner, false,
				       do_setlk_cpl_clb, fuse_io);
	}

	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_setlkw(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_lk_in *arg;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_lk_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fuse_io->u.setlkw.fhandle = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
	fuse_io->u.setlkw.owner = fsdev_io_d2h_u64(fuse_io->disp, arg->owner);

	err = fuse_to_fsdev_file_lock(fuse_io, &arg->lk, &fuse_io->u.setlkw.lock);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
		return;
	}

	/*
	 * Giving it a try to take the lock immediately. If it fails then the
	 * setlkw request is added to the wait list in do_setlkw_cpl_clb() and
	 * tries again and so on until the lock is acquired and file stays open.
	 */
	err = spdk_fsdev_setlk(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), file_handle(fuse_io->u.setlkw.fhandle),
			       &fuse_io->u.setlkw.lock, fuse_io->u.setlkw.owner, true,
			       do_setlkw_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_access_cpl_clb(void *cb_arg, struct spdk_io_channel *ch,
		  int status, uint32_t mask, uid_t uid, uid_t gid)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_access(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_access_in *arg;
	uint32_t mask;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_access_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	mask = fsdev_io_h2d_u32(fuse_io->disp, arg->mask);

	/* Using effective uid and gid. Without setuid they have uid of the process. */
	err = spdk_fsdev_access(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				file_object(fuse_io), mask, geteuid(), getegid(),
				do_access_cpl_clb, fuse_io);

	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_create_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status,
		  struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr,
		  struct spdk_fsdev_file_handle *fhandle)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_create(fuse_io, fobject, attr, fhandle);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_create(struct fuse_io *fuse_io)
{
	int err;
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;
	bool compat = fsdev_io_proto_minor(fuse_io) < 12;
	struct fuse_create_in *arg;
	const char *name;
	uint32_t flags, mode, umask = 0;
	size_t arg_size = compat ? sizeof(struct fuse_open_in) : sizeof(*arg);

	arg = _fsdev_io_in_arg_get_buf(fuse_io, arg_size);
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_create_in (compat=%d)\n", compat);
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	name = _fsdev_io_in_arg_get_str(fuse_io);
	if (!name) {
		SPDK_ERRLOG("Cannot get name (compat=%d)\n", compat);
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	mode =  fsdev_io_d2h_u32(fuse_io->disp, arg->mode);
	if (!compat) {
		umask = fsdev_io_d2h_u32(fuse_io->disp, arg->umask);
	}

	if (!fsdev_d2h_open_flags(disp->fuse_arch, fsdev_io_d2h_u32(fuse_io->disp, arg->flags), &flags)) {
		SPDK_ERRLOG("Cannot translate flags\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_create(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				file_object(fuse_io), name, mode, flags, umask, fuse_io->hdr.uid,
				fuse_io->hdr.gid, do_create_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_abort_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_interrupt(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_interrupt_in *arg;
	uint64_t unique;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_access_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	unique = fsdev_io_d2h_u64(fuse_io->disp, arg->unique);

	SPDK_DEBUGLOG(fuse_dispatcher, "INTERRUPT: %" PRIu64 "\n", unique);

	err = spdk_fsdev_abort(fuse_io_desc(fuse_io), fuse_io->ch, unique, do_abort_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_bmap(struct fuse_io *fuse_io)
{
	SPDK_ERRLOG("BMAP is not supported\n");
	fuse_dispatcher_io_complete_err(fuse_io, -ENOSYS);
}

static struct fuse_ioctl_iovec *
fsdev_ioctl_iovec_to_fuse_copy(struct fuse_io *fuse_io, const struct iovec *iov, size_t count)
{
	struct fuse_ioctl_iovec *fiov;
	size_t i;

	fiov = calloc(1, sizeof(struct fuse_ioctl_iovec) * count);
	if (!fiov) {
		return NULL;
	}

	for (i = 0; i < count; i++) {
		fiov[i].base = fsdev_io_h2d_u64(fuse_io->disp, (uint64_t)(uintptr_t)iov[i].iov_base);
		fiov[i].len = fsdev_io_h2d_u64(fuse_io->disp, (uint64_t)(uintptr_t)iov[i].iov_len);
	}

	return fiov;
}

static struct iovec *
fuse_ioctl_iovec_copy(const struct iovec *iov, size_t count)
{
	size_t size = sizeof(*iov) * count;
	struct iovec *result;

	assert(iov && count);

	result = calloc(1, size);
	if (!result) {
		return NULL;
	}
	memcpy(result, iov, size);
	return result;
}

typedef void (*fuse_dispatcher_ioctl_cpl_cb)(struct fuse_io *fuse_io, size_t size,
		int32_t out_flags, int32_t result,
		struct iovec *in_iov, uint32_t in_iovcnt,
		struct iovec *out_iov, uint32_t out_iovcnt);
/**
 * Unrestricted version of ioctl() completion callback.
 *
 * It returns ioctl() result in a set of fuse_ioctl_iovec and though it is
 * primarily used for FUSE_IOCTL_RETRY case it seems nothing stops it from being
 * used for a traditional ioctl() that gets/sets internal data tha size of which
 * is known and FUSE_IOCTL_RETRY is not required.
 */
static void
fuse_dispatcher_io_complete_unrestricted_ioctl(struct fuse_io *fuse_io, size_t size,
		int32_t out_flags, int32_t result,
		struct iovec *in_iov, uint32_t in_iovcnt,
		struct iovec *out_iov, uint32_t out_iovcnt)
{
	struct fuse_ioctl_iovec *fiov = NULL;
	struct fuse_ioctl_iovec *in_fiov = NULL;
	struct fuse_ioctl_iovec *out_fiov = NULL;

	if (in_iovcnt) {
		size_t in_size = sizeof(*fiov) * in_iovcnt;

		fiov = _fsdev_io_out_arg_get_buf(fuse_io, in_size);
		if (!fiov) {
			SPDK_ERRLOG("Cannot get ioctl iovec out buffer\n");
			fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
			return;
		}

		/* Converting to struct fuse_ioctl_iovec with uint64_t fields. */
		in_fiov = fsdev_ioctl_iovec_to_fuse_copy(fuse_io, in_iov, in_iovcnt);
		if (!in_fiov) {
			fuse_dispatcher_io_complete_err(fuse_io, -ENOMEM);
			return;
		}
		memcpy(fiov, in_fiov, in_size);
		size += in_size;
		free(in_fiov);
	}
	if (out_iovcnt) {
		size_t out_size = sizeof(*fiov) * out_iovcnt;

		fiov = _fsdev_io_out_arg_get_buf(fuse_io, out_size);
		if (!fiov) {
			SPDK_ERRLOG("Cannot get ioctl iovec out buffer\n");
			fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
			return;
		}

		/* Converting to struct fuse_ioctl_iovec with uint64_t fields. */
		out_fiov = fsdev_ioctl_iovec_to_fuse_copy(fuse_io, out_iov, out_iovcnt);
		if (!out_fiov) {
			fuse_dispatcher_io_complete_err(fuse_io, -ENOMEM);
			return;
		}
		memcpy(fiov, out_fiov, out_size);
		size += out_size;
		free(out_fiov);
	}

	fuse_dispatcher_io_complete_ok(fuse_io, size);
}

static void
fuse_dispatcher_io_complete_restricted_ioctl(struct fuse_io *fuse_io, size_t size,
		int32_t out_flags, int32_t result,
		struct iovec *in_iov, uint32_t in_iovcnt,
		struct iovec *out_iov, uint32_t out_iovcnt)
{
	if (in_iovcnt) {
		SPDK_ERRLOG("Got unexpected for restricted ioctl() input "
			    "buffer to be returned to the FUSE - ignoring.\n");
	}
	if (out_iovcnt) {
		SPDK_ERRLOG("Got unexpected for restricted ioctl() output "
			    "buffer to be returned to the FUSE - ignoring.\n");
	}

	/*
	 * The out buffer has already been populated (if any). Make sure to have
	 * correct size in the header.
	 */
	size += fuse_io->u.ioctl.out_size;

	fuse_dispatcher_io_complete_ok(fuse_io, size);
}

static void
fuse_dispatcher_io_complete_ioctl(struct fuse_io *fuse_io,
				  bool retry, int32_t result,
				  struct iovec *in_iov, uint32_t in_iovcnt,
				  struct iovec *out_iov, uint32_t out_iovcnt)
{
	struct fuse_ioctl_out *arg;
	fuse_dispatcher_ioctl_cpl_cb ioctl_cpl_cb;
	uint32_t in_flags = fuse_io->u.ioctl.flags;
	uint32_t out_flags = retry ? FUSE_IOCTL_RETRY : 0;

	arg = _fsdev_io_out_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_ioctl_out\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	arg->result = fsdev_io_h2d_u32(fuse_io->disp, (uint32_t)result);
	arg->flags = fsdev_io_h2d_u32(fuse_io->disp, out_flags);
	arg->in_iovs = fsdev_io_h2d_u32(fuse_io->disp, in_iovcnt);
	arg->out_iovs = fsdev_io_h2d_u32(fuse_io->disp, out_iovcnt);

	if (in_flags & FUSE_IOCTL_UNRESTRICTED) {
		ioctl_cpl_cb = fuse_dispatcher_io_complete_unrestricted_ioctl;
	} else {
		ioctl_cpl_cb = fuse_dispatcher_io_complete_restricted_ioctl;
	}

	ioctl_cpl_cb(fuse_io, sizeof(*arg), out_flags, result, in_iov, in_iovcnt,
		     out_iov, out_iovcnt);
}

static void
do_ioctl_cpl_clb(void *cb_arg, struct spdk_io_channel *ch,
		 int status, int32_t result,
		 struct iovec *in_iov, uint32_t in_iovcnt,
		 struct iovec *out_iov, uint32_t out_iovcnt)
{
	struct fuse_io *fuse_io = cb_arg;
	bool retry = (status == -EAGAIN);
	uint32_t in_flags = fuse_io->u.ioctl.flags;

	/*
	 * We get -EAGAIN on retry requested by the fsdev, this is not an error.
	 */
	if (retry) {
		/*
		 * Retry without FUSE_IOCTL_UNRESTRICTED is not allowed.
		 */
		status = (in_flags & FUSE_IOCTL_UNRESTRICTED) ? 0 : -EIO;
	} else if (!status && (in_iovcnt || out_iovcnt)) {
		/*
		 * The final stage (no retry case) should populate the data into
		 * the buffers. Retruning iovecs is not allowed and will corrupt
		 * the data.
		 */
		SPDK_ERRLOG("The FSDEV module populated some iovecs with in_iovcnt=%u "
			    "and out_iovcnt=%u for non-retry case, when it was supposed "
			    "to populate the data buffers only.\n", in_iovcnt, out_iovcnt);
		status = -EIO;
	}

	if (!status) {
		fuse_dispatcher_io_complete_ioctl(fuse_io, retry, result,
						  in_iov, in_iovcnt,
						  out_iov, out_iovcnt);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}

	/* Allocated in do_ioctl(). */
	free(fuse_io->u.ioctl.in_iov);
	free(fuse_io->u.ioctl.out_iov);
}

static void
do_ioctl(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_ioctl_in *in;
	uint64_t fh;
	uint32_t flags;
	uint32_t request;
	uint64_t arg;
	uint32_t in_size;
	uint32_t out_size;
	struct iovec in_iov[1];
	struct iovec out_iov[1];

	in = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*in));
	if (!in) {
		SPDK_ERRLOG("Cannot get fuse_ioctl_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	flags = fsdev_io_d2h_u32(fuse_io->disp, in->flags);

	/*
	 * FUSE_IOCTL_COMPAT is used when 32-bit user space app calls ioctl()
	 * on a 64-bit kernel.
	 */
	if (flags & (FUSE_IOCTL_COMPAT | FUSE_IOCTL_32BIT)) {
		SPDK_ERRLOG("Compat ioctl is not supported.\n");
		fuse_dispatcher_io_complete_err(fuse_io, -ENOTSUP);
		return;
	}

	/*
	 * Another compat flag. Not supported.
	 */
	if (flags & FUSE_IOCTL_COMPAT_X32) {
		SPDK_ERRLOG("Compat x32 ioctl is not supported.\n");
		fuse_dispatcher_io_complete_err(fuse_io, -ENOTSUP);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, in->fh);
	request = fsdev_io_d2h_u32(fuse_io->disp, in->cmd);
	in_size = fsdev_io_d2h_u32(fuse_io->disp, in->in_size);
	out_size = fsdev_io_d2h_u32(fuse_io->disp, in->out_size);
	arg = fsdev_io_d2h_u64(fuse_io->disp, in->arg);

	if (in_size) {
		in_iov[0].iov_base = _fsdev_io_in_arg_get_buf(fuse_io, in_size);
		if (!in_iov[0].iov_base) {
			SPDK_ERRLOG("Failed to get input buf of size=%u\n", in_size);
			fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
			return;
		}
		in_iov[0].iov_len = in_size;

		fuse_io->u.ioctl.in_iov = fuse_ioctl_iovec_copy(in_iov, 1);
		if (!fuse_io->u.ioctl.in_iov) {
			SPDK_ERRLOG("Cannot alloc ioctl iovecs.\n");
			fuse_dispatcher_io_complete_err(fuse_io, -ENOMEM);
			return;
		}
		fuse_io->u.ioctl.in_iovcnt = 1;
	} else {
		fuse_io->u.ioctl.in_iov = NULL;
		fuse_io->u.ioctl.in_iovcnt = 0;
	}

	/*
	 * Getting out buffer to avoid copying allow the fsdev to use it directly
	 * for any returned data.
	 */
	if (out_size) {
		char *buff;

		/* Preserve the out offset. */
		struct iov_offs out_offs_bu = fuse_io->out_offs;

		/* Skip the fuse_ioctl_out. */
		_fsdev_io_out_arg_get_buf(fuse_io, sizeof(struct fuse_ioctl_out));

		/* Get the buffer for the out iovec. */
		buff = _fsdev_io_out_arg_get_buf(fuse_io, out_size);
		if (!buff) {
			SPDK_INFOLOG(fuse_dispatcher, "Got NULL ioctl out buffer.\n");
			err = -EINVAL;
			goto out_err;
		}

		/*
		 * Restore the out offset so it works on populating the output in
		 * comeption cb.
		 */
		fuse_io->out_offs = out_offs_bu;

		out_iov[0].iov_base = buff;
		out_iov[0].iov_len = out_size;

		fuse_io->u.ioctl.out_iov = fuse_ioctl_iovec_copy(out_iov, 1);
		if (!fuse_io->u.ioctl.out_iov) {
			SPDK_ERRLOG("Cannot alloc ioctl iovecs.\n");
			err = -ENOMEM;
			goto out_err;
		}
		fuse_io->u.ioctl.out_iovcnt = 1;
	} else {
		fuse_io->u.ioctl.out_iov = NULL;
		fuse_io->u.ioctl.out_iovcnt = 0;
	}

	/* Used in the completion cb for checking UNRESTRICTED & RETRY flags. */
	fuse_io->u.ioctl.flags = flags;
	fuse_io->u.ioctl.out_size = out_size;

	err = spdk_fsdev_ioctl(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), file_handle(fh), request, arg,
			       fuse_io->u.ioctl.in_iov, fuse_io->u.ioctl.in_iovcnt,
			       fuse_io->u.ioctl.out_iov, fuse_io->u.ioctl.out_iovcnt,
			       do_ioctl_cpl_clb, fuse_io);

out_err:
	if (err) {
		free(fuse_io->u.ioctl.in_iov);
		free(fuse_io->u.ioctl.out_iov);
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_poll_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status, uint32_t revents)
{
	struct fuse_io *fuse_io = cb_arg;

	if (status == 0) {
		/* Events available, completing the operation. */
		fuse_dispatcher_io_complete_poll(fuse_io, revents);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_poll(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_poll_in *arg;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_poll_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fuse_io->u.poll.fhandle = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
	fuse_io->u.poll.events = fuse_events_to_fsdev(fsdev_io_d2h_u32(fuse_io->disp, arg->events));

	err = spdk_fsdev_poll(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			      file_object(fuse_io), file_handle(fuse_io->u.poll.fhandle),
			      fuse_io->u.poll.events, true, do_poll_cpl_clb, fuse_io);

	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

#define FALLOC_FLAGS_MAP \
	FALLOC_FLAG(FL_KEEP_SIZE)      \
	FALLOC_FLAG(FL_PUNCH_HOLE)     \
	FALLOC_FLAG(FL_NO_HIDE_STALE)  \
	FALLOC_FLAG(FL_COLLAPSE_RANGE) \
	FALLOC_FLAG(FL_ZERO_RANGE)     \
	FALLOC_FLAG(FL_INSERT_RANGE)   \
	FALLOC_FLAG(FL_UNSHARE_RANGE)

static uint32_t
fuse_falloc_flags_to_fsdev(uint32_t flags)
{
	uint32_t result = 0;

#define FALLOC_FLAG(name) \
	if (flags & FALLOC_##name) {                \
		result |= SPDK_FSDEV_FALLOC_##name; \
	}

	FALLOC_FLAGS_MAP;

#undef FALLOC_FLAG

	return result;
}

static void
do_fallocate_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_fallocate(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_fallocate_in *arg;
	uint32_t mode;
	uint64_t fh;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_fallocate_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
	mode = fuse_falloc_flags_to_fsdev(fsdev_io_d2h_u32(fuse_io->disp, arg->mode));

	err = spdk_fsdev_fallocate(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				   file_object(fuse_io), file_handle(fh),
				   mode, fsdev_io_d2h_u64(fuse_io->disp, arg->offset),
				   fsdev_io_d2h_u64(fuse_io->disp, arg->length),
				   do_fallocate_cpl_clb, fuse_io);
	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_umount_cpl_clb(void *cb_arg, struct spdk_io_channel *ch)
{
	struct fuse_io *fuse_io = cb_arg;
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;

	disp->proto_major = disp->proto_minor = 0;
	disp->root_fobject = NULL;
	SPDK_DEBUGLOG(fuse_dispatcher, "%s unmounted\n", fuse_dispatcher_name(disp));

	/* Save the state */
	fuse_dispatcher_update_rmem(disp);

	fuse_dispatcher_io_complete_err(fuse_io, 0);
}

static void
do_destroy(struct fuse_io *fuse_io)
{
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;
	int rc;

	rc = spdk_fsdev_umount(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique, do_umount_cpl_clb,
			       fuse_io);
	if (rc) {
		SPDK_ERRLOG("%s: failed to initiate umount (err=%d)\n", fuse_dispatcher_name(disp), rc);
		fuse_dispatcher_io_complete_err(fuse_io, rc);
		return;
	}
}

static void
do_batch_forget_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	if (status) {
		fuse_io->u.batch_forget.status = status;
	}

	fuse_io->u.batch_forget.to_forget--;

	if (!fuse_io->u.batch_forget.to_forget) {
		/* FUSE_BATCH_FORGET requires no response */
		fuse_dispatcher_io_complete_none(fuse_io, fuse_io->u.batch_forget.status);
	}
}

static void
do_batch_forget(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_batch_forget_in *arg;
	struct fuse_forget_data *forgets;
	size_t scount;
	uint32_t count, i;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_batch_forget_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	/* Prevent integer overflow.  The compiler emits the following warning
	 * unless we use the scount local variable:
	 *
	 * error: comparison is always false due to limited range of data type
	 * [-Werror=type-limits]
	 *
	 * This may be true on 64-bit hosts but we need this check for 32-bit
	 * hosts.
	 */
	scount = fsdev_io_d2h_u32(fuse_io->disp, arg->count);
	if (scount > SIZE_MAX / sizeof(forgets[0])) {
		SPDK_WARNLOG("Too many forgets (%zu >= %zu)\n", scount,
			     SIZE_MAX / sizeof(forgets[0]));
		/* FUSE_BATCH_FORGET requires no response */
		fuse_dispatcher_io_complete_none(fuse_io, -EINVAL);
		return;
	}

	count = scount;
	if (!count) {
		SPDK_WARNLOG("0 forgets requested\n");
		/* FUSE_BATCH_FORGET requires no response */
		fuse_dispatcher_io_complete_none(fuse_io, -EINVAL);
		return;
	}

	forgets = _fsdev_io_in_arg_get_buf(fuse_io, count * sizeof(forgets[0]));
	if (!forgets) {
		SPDK_WARNLOG("Cannot get expected forgets (%" PRIu32 ")\n", count);
		/* FUSE_BATCH_FORGET requires no response */
		fuse_dispatcher_io_complete_none(fuse_io, -EINVAL);
		return;
	}

	fuse_io->u.batch_forget.to_forget = 0;
	fuse_io->u.batch_forget.status = 0;

	for (i = 0; i < count; i++) {
		uint64_t ino = fsdev_io_d2h_u64(fuse_io->disp, forgets[i].ino);
		uint64_t nlookup = fsdev_io_d2h_u64(fuse_io->disp, forgets[i].nlookup);
		err = spdk_fsdev_forget(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
					ino_to_object(fuse_io, ino), nlookup,
					do_batch_forget_cpl_clb, fuse_io);
		if (!err) {
			fuse_io->u.batch_forget.to_forget++;
		} else {
			fuse_io->u.batch_forget.status = err;
		}
	}

	if (!fuse_io->u.batch_forget.to_forget) {
		/* FUSE_BATCH_FORGET requires no response */
		fuse_dispatcher_io_complete_none(fuse_io, fuse_io->u.batch_forget.status);
	}
}

static void
do_lseek_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status, off_t offset,
		 enum spdk_fsdev_seek_whence whence)
{
	struct fuse_io *fuse_io = cb_arg;

	if (!status) {
		fuse_dispatcher_io_complete_lseek(fuse_io, offset);
	} else {
		fuse_dispatcher_io_complete_err(fuse_io, status);
	}
}

static void
do_lseek(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_lseek_in *arg;
	uint64_t fh;
	uint64_t offset;
	enum spdk_fsdev_seek_whence whence;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_lseek_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh = fsdev_io_d2h_u64(fuse_io->disp, arg->fh);
	offset = fsdev_io_d2h_u64(fuse_io->disp, arg->offset);

	switch (fsdev_io_d2h_u32(fuse_io->disp, arg->whence)) {
	case SEEK_SET:
		whence = SPDK_FSDEV_SEEK_SET;
		break;
	case SEEK_CUR:
		whence = SPDK_FSDEV_SEEK_CUR;
		break;
	case SEEK_END:
		whence = SPDK_FSDEV_SEEK_END;
		break;
	case SEEK_DATA:
		whence = SPDK_FSDEV_SEEK_DATA;
		break;
	case SEEK_HOLE:
		whence = SPDK_FSDEV_SEEK_HOLE;
		break;
	default:
		SPDK_ERRLOG("Invalid whence %d in fuse_lseek_in\n", fsdev_io_d2h_u32(fuse_io->disp, arg->whence));
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_lseek(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
			       file_object(fuse_io), file_handle(fh), offset, whence,
			       do_lseek_cpl_clb, fuse_io);

	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_copy_file_range_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status, uint32_t data_size)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_write(fuse_io, data_size, status);
}

static void
do_copy_file_range(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_copy_file_range_in *arg;
	uint64_t fh_in, fh_out, nodeid_out;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_copy_file_range_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	fh_in = fsdev_io_d2h_u64(fuse_io->disp, arg->fh_in);
	nodeid_out = fsdev_io_d2h_u64(fuse_io->disp, arg->nodeid_out);
	fh_out = fsdev_io_d2h_u64(fuse_io->disp, arg->fh_out);

	err = spdk_fsdev_copy_file_range(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
					 file_object(fuse_io), file_handle(fh_in),
					 fsdev_io_d2h_u64(fuse_io->disp, arg->off_in),
					 ino_to_object(fuse_io, nodeid_out), file_handle(fh_out),
					 fsdev_io_d2h_u64(fuse_io->disp, arg->off_out),
					 fsdev_io_d2h_u64(fuse_io->disp, arg->len),
					 fsdev_io_d2h_u64(fuse_io->disp, arg->flags),
					 do_copy_file_range_cpl_clb, fuse_io);

	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_setupmapping(struct fuse_io *fuse_io)
{
	SPDK_ERRLOG("SETUPMAPPING is not supported\n");
	fuse_dispatcher_io_complete_err(fuse_io, -ENOSYS);
}

static void
do_removemapping(struct fuse_io *fuse_io)
{
	SPDK_ERRLOG("REMOVEMAPPING is not supported\n");
	fuse_dispatcher_io_complete_err(fuse_io, -ENOSYS);
}

static void
do_syncfs_cpl_clb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_dispatcher_io_complete_err(fuse_io, status);
}

static void
do_syncfs(struct fuse_io *fuse_io)
{
	int err;
	struct fuse_syncfs_in *arg;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get fuse_syncfs_in\n");
		fuse_dispatcher_io_complete_err(fuse_io, -EINVAL);
		return;
	}

	err = spdk_fsdev_syncfs(fuse_io_desc(fuse_io), fuse_io->ch, fuse_io->hdr.unique,
				file_object(fuse_io), do_syncfs_cpl_clb, fuse_io);

	if (err) {
		fuse_dispatcher_io_complete_err(fuse_io, err);
	}
}

static void
do_notify_reply(struct fuse_io *fuse_io)
{
	struct fuse_notify_reply_in *arg;
	struct spdk_fsdev_notify_reply_data notify_reply_data;

	arg = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*arg));
	if (!arg) {
		SPDK_ERRLOG("Cannot get virtiofs_reply_in: unique %" PRIu64", len %u\n",
			    fuse_io->hdr.unique, fuse_io->hdr.len);
		fuse_dispatcher_io_complete_none(fuse_io, -EINVAL);
		return;
	}

	SPDK_INFOLOG(fuse_dispatcher, "FUSE_NOTIFY_REPLY: unique %" PRIu64 ", len %u, error %d\n",
		     fuse_io->hdr.unique, fuse_io->hdr.len, arg->error);
	if (fuse_io->disp->notify_reply_cb) {
		notify_reply_data.status = fsdev_io_h2d_i32(fuse_io->disp, arg->error);
		fuse_io->disp->notify_reply_cb(fuse_io->disp->notify_reply_cb_arg, &notify_reply_data,
					       fuse_io->hdr.unique);
	}

	fuse_dispatcher_io_complete_none(fuse_io, 0);
}

static const struct {
	void (*func)(struct fuse_io *fuse_io);
	const char *name;
} fuse_ll_ops[] = {
	[FUSE_LOOKUP]	   = { do_lookup,      "LOOKUP"	     },
	[FUSE_FORGET]	   = { do_forget,      "FORGET"	     },
	[FUSE_GETATTR]	   = { do_getattr,     "GETATTR"     },
	[FUSE_SETATTR]	   = { do_setattr,     "SETATTR"     },
	[FUSE_READLINK]	   = { do_readlink,    "READLINK"    },
	[FUSE_SYMLINK]	   = { do_symlink,     "SYMLINK"     },
	[FUSE_MKNOD]	   = { do_mknod,       "MKNOD"	     },
	[FUSE_MKDIR]	   = { do_mkdir,       "MKDIR"	     },
	[FUSE_UNLINK]	   = { do_unlink,      "UNLINK"	     },
	[FUSE_RMDIR]	   = { do_rmdir,       "RMDIR"	     },
	[FUSE_RENAME]	   = { do_rename,      "RENAME"	     },
	[FUSE_LINK]	   = { do_link,	       "LINK"	     },
	[FUSE_OPEN]	   = { do_open,	       "OPEN"	     },
	[FUSE_READ]	   = { do_read,       "READ"	     },
	[FUSE_WRITE]	   = { do_write,       "WRITE"	     },
	[FUSE_STATFS]	   = { do_statfs,      "STATFS"	     },
	[FUSE_RELEASE]	   = { do_release,     "RELEASE"     },
	[FUSE_FSYNC]	   = { do_fsync,       "FSYNC"	     },
	[FUSE_SETXATTR]	   = { do_setxattr,    "SETXATTR"    },
	[FUSE_GETXATTR]	   = { do_getxattr,    "GETXATTR"    },
	[FUSE_LISTXATTR]   = { do_listxattr,   "LISTXATTR"   },
	[FUSE_REMOVEXATTR] = { do_removexattr, "REMOVEXATTR" },
	[FUSE_FLUSH]	   = { do_flush,       "FLUSH"	     },
	[FUSE_INIT]	   = { do_init,	       "INIT"	     },
	[FUSE_OPENDIR]	   = { do_opendir,     "OPENDIR"     },
	[FUSE_READDIR]	   = { do_readdir,     "READDIR"     },
	[FUSE_RELEASEDIR]  = { do_releasedir,  "RELEASEDIR"  },
	[FUSE_FSYNCDIR]	   = { do_fsyncdir,    "FSYNCDIR"    },
	[FUSE_GETLK]	   = { do_getlk,       "GETLK"	     },
	[FUSE_SETLK]	   = { do_setlk,       "SETLK"	     },
	[FUSE_SETLKW]	   = { do_setlkw,      "SETLKW"	     },
	[FUSE_ACCESS]	   = { do_access,      "ACCESS"	     },
	[FUSE_CREATE]	   = { do_create,      "CREATE"	     },
	[FUSE_INTERRUPT]   = { do_interrupt,   "INTERRUPT"   },
	[FUSE_BMAP]	   = { do_bmap,	       "BMAP"	     },
	[FUSE_IOCTL]	   = { do_ioctl,       "IOCTL"	     },
	[FUSE_POLL]	   = { do_poll,        "POLL"	     },
	[FUSE_FALLOCATE]   = { do_fallocate,   "FALLOCATE"   },
	[FUSE_DESTROY]	   = { do_destroy,     "DESTROY"     },
	[FUSE_NOTIFY_REPLY] = { do_notify_reply, "NOTIFY_REPLY" },
	[FUSE_BATCH_FORGET] = { do_batch_forget, "BATCH_FORGET" },
	[FUSE_READDIRPLUS] = { do_readdirplus,	"READDIRPLUS"},
	[FUSE_RENAME2]     = { do_rename2,      "RENAME2"    },
	[FUSE_COPY_FILE_RANGE] = { do_copy_file_range, "COPY_FILE_RANGE" },
	[FUSE_SETUPMAPPING]  = { do_setupmapping, "SETUPMAPPING" },
	[FUSE_REMOVEMAPPING] = { do_removemapping, "REMOVEMAPPING" },
	[FUSE_SYNCFS] = { do_syncfs, "SYNCFS" },
	[FUSE_LSEEK] = { do_lseek, "LSEEK" },
};

static int
spdk_fuse_dispatcher_handle_fuse_req(struct spdk_fuse_dispatcher *disp, struct fuse_io *fuse_io)
{
	struct fuse_in_header *hdr;

	if (!fuse_io->in_iovcnt || !fuse_io->in_iov) {
		SPDK_ERRLOG("Bad IO: no IN iov (%d, %p)\n", fuse_io->in_iovcnt, fuse_io->in_iov);
		goto exit;
	}

	hdr = _fsdev_io_in_arg_get_buf(fuse_io, sizeof(*hdr));
	if (!hdr) {
		SPDK_ERRLOG("Bad IO: cannot get fuse_in_header\n");
		goto exit;
	}

	fuse_io->hdr.opcode = fsdev_io_d2h_u32(fuse_io->disp, hdr->opcode);

	if (spdk_unlikely(!fuse_io->ch)) {
		/* The fsdev is not currently active. Complete this request. */
		SPDK_ERRLOG("IO (%" PRIu32 ") arrived while there's no channel\n", fuse_io->hdr.opcode);
		goto exit;
	}

	if (spdk_likely(_fuse_op_requires_reply(hdr->opcode))) {
		struct fuse_out_header *out_hdr = _fsdev_io_out_arg_get_buf(fuse_io, sizeof(*out_hdr));
		if (!out_hdr) {
			SPDK_ERRLOG("Bad IO: cannot get out_hdr\n");
			goto exit;
		}

		UNUSED(out_hdr); /* We don't need it here, we just made a check and a reservation */
	}

	if (fuse_io->hdr.opcode >= SPDK_COUNTOF(fuse_ll_ops)) {
		SPDK_ERRLOG("Bad IO: opt_code is out of range (%" PRIu32 " > %zu)\n", fuse_io->hdr.opcode,
			    SPDK_COUNTOF(fuse_ll_ops));
		fuse_dispatcher_io_complete_err(fuse_io, -ENOSYS);
		return 0;
	}

	if (!fuse_ll_ops[fuse_io->hdr.opcode].func) {
		SPDK_ERRLOG("Bad IO: no handler for (%" PRIu32 ") %s\n", fuse_io->hdr.opcode,
			    fuse_ll_ops[fuse_io->hdr.opcode].name);
		fuse_dispatcher_io_complete_err(fuse_io, -ENOSYS);
		return 0;
	}

	fuse_io->hdr.len = fsdev_io_d2h_u32(fuse_io->disp, hdr->len);
	fuse_io->hdr.unique = fsdev_io_d2h_u64(fuse_io->disp, hdr->unique);
	fuse_io->hdr.nodeid = fsdev_io_d2h_u64(fuse_io->disp, hdr->nodeid);
	fuse_io->hdr.uid = fsdev_io_d2h_u32(fuse_io->disp, hdr->uid);
	fuse_io->hdr.gid = fsdev_io_d2h_u32(fuse_io->disp, hdr->gid);
	fuse_io->hdr.pid = fsdev_io_d2h_u32(fuse_io->disp, hdr->pid);

	SPDK_DEBUGLOG(fuse_dispatcher, "IO arrived: %" PRIu32 " (%s) len=%" PRIu32 " unique=%" PRIu64
		      " nodeid=0x%" PRIx64 " uid=%" PRIu32 " gid=%" PRIu32 " pid=%" PRIu32 "\n", fuse_io->hdr.opcode,
		      fuse_ll_ops[fuse_io->hdr.opcode].name, fuse_io->hdr.len, fuse_io->hdr.unique,
		      fuse_io->hdr.nodeid, fuse_io->hdr.uid, fuse_io->hdr.gid, fuse_io->hdr.pid);

	fuse_ll_ops[fuse_io->hdr.opcode].func(fuse_io);
	return 0;

exit:
	return -EINVAL;
}

static bool
fuse_dispatcher_create_rmem(struct spdk_fuse_dispatcher *disp, char *rmem_pool_name)
{
	disp->rmem_pool = spdk_rmem_pool_create(rmem_pool_name, sizeof(struct fuse_disp_recovery_data),
						1, 1);
	if (!disp->rmem_pool) {
		SPDK_ERRLOG("%s: failed to create rmem pool", rmem_pool_name);
		return false;
	}

	disp->rmem_data = spdk_rmem_pool_get(disp->rmem_pool);
	if (!disp->rmem_data) {
		SPDK_ERRLOG("%s: failed to get rmem_data\n", rmem_pool_name);
		spdk_rmem_pool_destroy(disp->rmem_pool);
		return false;
	}

	/* Save the initial state */
	fuse_dispatcher_update_rmem(disp);

	SPDK_NOTICELOG("%s: rmem pool created succesfully\n", rmem_pool_name);
	return true;
}

static int
fuse_dispatcher_rmem_restore_block_cb(struct spdk_rmem_entry *entry, void *ctx)
{
	struct fuse_disp_recovery_data data;
	struct spdk_fuse_dispatcher *disp = ctx;

	if (disp->rmem_data) {
		SPDK_ERRLOG("%s: data has already been restored. Duplicated entry?\n",
			    fuse_dispatcher_name(disp));
		return -EIO;
	}

	if (!spdk_rmem_entry_read(entry, &data)) {
		SPDK_ERRLOG("%s: failed to read restored entry\n",
			    fuse_dispatcher_name(disp));
		return -ENODATA;
	}

	disp->rmem_data = entry;
	disp->proto_major = data.proto_major;
	disp->proto_minor = data.proto_minor;
	disp->root_fobject = (struct spdk_fsdev_file_object *)(uintptr_t)data.root_fobject;

	SPDK_NOTICELOG("%s: data restored: proto_major=%u proto_minor=%u root_fobject=0x%p\n",
		       fuse_dispatcher_name(disp), disp->proto_major, disp->proto_minor, disp->root_fobject);

	return 0;
}

static bool
fuse_dispatcher_recover_rmem(struct spdk_fuse_dispatcher *disp, char *rmem_pool_name)
{
	disp->rmem_pool = spdk_rmem_pool_restore(rmem_pool_name, sizeof(struct fuse_disp_recovery_data),
			  fuse_dispatcher_rmem_restore_block_cb, disp);
	if (!disp->rmem_pool) {
		SPDK_ERRLOG("%s: failed to restore rmem pool\n", rmem_pool_name);
		return false;
	}

	SPDK_NOTICELOG("%s: rmem pool restored successfully\n", rmem_pool_name);
	return true;
}

static bool
fuse_dispatcher_init_rmem(struct spdk_fuse_dispatcher *disp, bool recovery_mode)
{
	bool res = false;
	char *rmem_pool_name;

	if (!spdk_rmem_is_enabled()) {
		SPDK_NOTICELOG("rmem is disabled\n");
		return true;
	}

	rmem_pool_name = spdk_sprintf_alloc("fuse_disp_%s", fuse_dispatcher_name(disp));
	if (!rmem_pool_name) {
		SPDK_ERRLOG("could not allocate pool name for %s\n", fuse_dispatcher_name(disp));
		return false;
	}

	res = recovery_mode ? fuse_dispatcher_recover_rmem(disp, rmem_pool_name) :
	      fuse_dispatcher_create_rmem(disp, rmem_pool_name);

	free(rmem_pool_name);

	return res;
}

struct spdk_fuse_dispatcher *
spdk_fuse_dispatcher_create(struct spdk_fsdev_desc *desc, bool recovery_mode,
			    spdk_fuse_dispatcher_notify_reply_cb notify_reply_cb,
			    void *notify_reply_cb_arg)
{
	struct spdk_fuse_dispatcher *disp;

	disp = calloc(1, sizeof(*disp));
	if (!disp) {
		SPDK_ERRLOG("could not allocate disp\n");
		return NULL;
	}

	disp->fuse_arch = SPDK_FUSE_ARCH_NATIVE;
	disp->desc = desc;
	disp->notify_reply_cb = notify_reply_cb;
	disp->notify_reply_cb_arg = notify_reply_cb_arg;

	if (!fuse_dispatcher_init_rmem(disp, recovery_mode)) {
		SPDK_ERRLOG("could not create or restore rmem pool for %s\n", fuse_dispatcher_name(disp));
		free(disp);
		return NULL;
	}

	return disp;
}

int
spdk_fuse_dispatcher_set_arch(struct spdk_fuse_dispatcher *disp, enum spdk_fuse_arch fuse_arch)
{
	switch (fuse_arch) {
	case SPDK_FUSE_ARCH_NATIVE:
	case SPDK_FUSE_ARCH_X86:
	case SPDK_FUSE_ARCH_X86_64:
	case SPDK_FUSE_ARCH_ARM:
	case SPDK_FUSE_ARCH_ARM64:
		SPDK_NOTICELOG("FUSE arch set to %d\n", fuse_arch);
		disp->fuse_arch = fuse_arch;
		return 0;
	default:
		return -EINVAL;
	}
}

size_t
spdk_fuse_dispatcher_get_io_ctx_size(void)
{
	return sizeof(struct fuse_io);
}

int
spdk_fuse_dispatcher_submit_request(struct spdk_fuse_dispatcher *disp,
				    struct spdk_io_channel *ch,
				    struct iovec *in_iov, int in_iovcnt,
				    struct iovec *out_iov, int out_iovcnt, void *io_ctx,
				    spdk_fuse_dispatcher_submit_cpl_cb clb, void *cb_arg)
{
	struct fuse_io *fuse_io = (struct fuse_io *) io_ctx;

	if (!fuse_io) {
		SPDK_ERRLOG("Invalid argument, fuse_io is NULL\n");
		return -ENOBUFS;
	}

	fuse_io->disp = disp;
	fuse_io->ch = ch;
	fuse_io->in_iov = in_iov;
	fuse_io->in_iovcnt = in_iovcnt;
	fuse_io->out_iov = out_iov;
	fuse_io->out_iovcnt = out_iovcnt;
	fuse_io->cpl_cb = clb;
	fuse_io->cpl_cb_arg = cb_arg;

	fuse_io->in_offs.iov_offs = 0;
	fuse_io->in_offs.buf_offs = 0;
	fuse_io->out_offs.iov_offs = 0;
	fuse_io->out_offs.buf_offs = 0;

	return spdk_fuse_dispatcher_handle_fuse_req(disp, fuse_io);
}

void
spdk_fuse_dispatcher_delete(struct spdk_fuse_dispatcher *disp)
{
	if (disp->rmem_data) {
		assert(disp->rmem_pool != NULL);
		spdk_rmem_entry_release(disp->rmem_data);
		spdk_rmem_pool_destroy(disp->rmem_pool);
	}
	free(disp);
}

static int
fuse_dispatcher_encode_notify_inval_inode(struct spdk_fuse_dispatcher *disp,
		struct fuse_out_header *out_hdr,
		size_t buf_size,
		const struct spdk_fsdev_notify_data *notify_data)
{
	struct fuse_notify_inval_inode_out *inval_inode;

	out_hdr->error = fsdev_io_d2h_i32(disp, FUSE_NOTIFY_INVAL_INODE);
	out_hdr->len = fsdev_io_d2h_u32(disp,
					sizeof(struct fuse_out_header) + sizeof(struct fuse_notify_inval_inode_out));

	if (out_hdr->len > buf_size) {
		SPDK_ERRLOG("Buffer is too small for notification, buf_size %lu, notify_size %d\n",
			    buf_size, out_hdr->len);
		return -ENOMEM;
	}

	inval_inode = (struct fuse_notify_inval_inode_out *)(out_hdr + 1);
	inval_inode->ino = fsdev_io_d2h_u64(disp, file_ino(disp, notify_data->inval_data.fobject));
	inval_inode->off = fsdev_io_d2h_u64(disp, notify_data->inval_data.offset);
	inval_inode->len = fsdev_io_d2h_u64(disp, notify_data->inval_data.size);
	return 0;
}

static int
fuse_dispatcher_encode_notify_inval_entry(struct spdk_fuse_dispatcher *disp,
		struct fuse_out_header *out_hdr,
		size_t buf_size,
		const struct spdk_fsdev_notify_data *notify_data)
{
	struct fuse_notify_inval_entry_out *inval_entry;
	char *name;
	size_t namelen;

	namelen = strlen(notify_data->inval_entry.name);
	out_hdr->error = fsdev_io_d2h_i32(disp, FUSE_NOTIFY_INVAL_ENTRY);
	out_hdr->len = fsdev_io_d2h_u32(disp,
					sizeof(struct fuse_out_header) + sizeof(struct fuse_notify_inval_entry_out) + namelen);

	if (out_hdr->len > buf_size) {
		SPDK_ERRLOG("Buffer is too small for notification, buf_size %lu, notify_size %d\n",
			    buf_size, out_hdr->len);
		return -ENOMEM;
	}

	inval_entry = (struct fuse_notify_inval_entry_out *)(out_hdr + 1);
	inval_entry->parent =
		fsdev_io_d2h_u64(disp, file_ino(disp, notify_data->inval_entry.parent_fobject));
	inval_entry->namelen = fsdev_io_d2h_u32(disp, namelen);
	name = (char *)(out_hdr + 1) + sizeof(*inval_entry);
	memcpy(name, notify_data->inval_entry.name, namelen);
	return 0;
}

int
spdk_fuse_dispatcher_encode_notify(struct spdk_fuse_dispatcher *disp,
				   struct iovec *iov, int iovcnt,
				   const struct spdk_fsdev_notify_data *notify_data,
				   uint64_t unique_id,
				   bool *has_reply)
{
	struct fuse_out_header *out_hdr;
	size_t buf_size;
	bool tmp_has_reply = false;
	int i;
	int rc = 0;

	for (i = 0, buf_size = 0; i < iovcnt; buf_size += iov[i].iov_len, ++i);
	assert(buf_size >= sizeof(struct fuse_out_header));
	out_hdr = malloc(buf_size);
	if (!out_hdr) {
		SPDK_ERRLOG("Failed to allocate bounce buffer for fuse notification, buf_size %lu\n", buf_size);
		return -ENOMEM;
	}

	if (notify_data) {
		out_hdr->unique = fsdev_io_d2h_u64(disp, unique_id);
		switch (notify_data->type) {
		case SPDK_FSDEV_NOTIFY_INVAL_DATA:
			rc = fuse_dispatcher_encode_notify_inval_inode(disp, out_hdr, buf_size, notify_data);
			tmp_has_reply = true;
			break;
		case SPDK_FSDEV_NOTIFY_INVAL_ENTRY:
			rc = fuse_dispatcher_encode_notify_inval_entry(disp, out_hdr, buf_size, notify_data);
			tmp_has_reply = true;
			break;
		default:
			SPDK_ERRLOG("Unsupported notify type %d\n", notify_data->type);
			rc = -EINVAL;
			break;
		}
	} else {
		/* error and unique set to zero indicate device reset to driver */
		out_hdr->len = fsdev_io_d2h_u32(disp, sizeof(*out_hdr));
		out_hdr->error = 0;
		out_hdr->unique = 0;
	}

	if (rc == 0) {
		*has_reply = tmp_has_reply;
		spdk_copy_buf_to_iovs(iov, iovcnt, out_hdr, out_hdr->len);
	}

	free(out_hdr);
	return rc;
}

uint32_t
spdk_fuse_dispatcher_get_notify_buf_size(struct spdk_fuse_dispatcher *disp)
{
	const uint32_t max_header_size = sizeof(struct fuse_out_header) +
					 sizeof(struct fuse_notify_retrieve_out);
	uint32_t buf_size = spdk_fsdev_get_notify_max_data_size(spdk_fsdev_desc_get_fsdev(disp->desc));

	if (buf_size) {
		buf_size += max_header_size;
	}

	return buf_size;
}

SPDK_LOG_REGISTER_COMPONENT(fuse_dispatcher)
