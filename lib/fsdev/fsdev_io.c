/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/fsdev.h"
#include "spdk/fsdev_module.h"
#include "spdk/log.h"
#include "spdk/likely.h"
#include "fsdev_internal.h"

static struct spdk_fsdev_io *
fsdev_io_get_and_fill(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		      void *usr_cb_fn, void *usr_cb_arg, enum spdk_fsdev_io_type type)
{
	struct spdk_fsdev_io *fsdev_io;
	struct spdk_fsdev_channel *channel = __io_ch_to_fsdev_ch(ch);

	channel->stat->io[type].count++;

	fsdev_io = fsdev_channel_get_io(channel);
	if (!fsdev_io) {
		channel->stat->num_out_of_io++;
		return NULL;
	}

	fsdev_io->fsdev = spdk_fsdev_desc_get_fsdev(desc);
	fsdev_io->internal.ch = channel;
	fsdev_io->internal.desc = desc;
	fsdev_io->internal.type = type;
	fsdev_io->internal.unique = unique;
	fsdev_io->internal.usr_cb_fn = usr_cb_fn;
	fsdev_io->internal.usr_cb_arg = usr_cb_arg;
	fsdev_io->internal.status = -ENOSYS;
	fsdev_io->internal.in_submit_request = false;
	fsdev_io->internal.submit_tsc = spdk_get_ticks();
	fsdev_io->internal.cleanup_cb_fn = NULL;

	return fsdev_io;
}

int
spdk_fsdev_mount(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		 uint64_t unique, const struct spdk_fsdev_mount_opts *opts,
		 spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_MOUNT);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.mount.opts = *opts;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_umount(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		  uint64_t unique, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_UMOUNT);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io_submit(fsdev_io);
	return 0;

}

int
spdk_fsdev_lseek(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		 uint64_t unique, struct spdk_fsdev_file_object *fobject,
		 struct spdk_fsdev_file_handle *fhandle, off_t offset,
		 enum spdk_fsdev_seek_whence whence, spdk_fsdev_cpl_cb cb_fn,
		 void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_LSEEK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.lseek.fobject = fobject;
	fsdev_io->u_in.lseek.fhandle = fhandle;
	fsdev_io->u_in.lseek.offset = offset;
	fsdev_io->u_in.lseek.whence = whence;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_poll(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		uint64_t unique, struct spdk_fsdev_file_object *fobject,
		struct spdk_fsdev_file_handle *fhandle, uint32_t events,
		bool wait, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_POLL);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.poll.fobject = fobject;
	fsdev_io->u_in.poll.fhandle = fhandle;
	fsdev_io->u_in.poll.events = events;
	fsdev_io->u_in.poll.wait = wait;

	fsdev_io_submit(fsdev_io);
	return 0;

}

int
spdk_fsdev_lookup(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		  struct spdk_fsdev_file_object *parent_fobject, const char *name,
		  spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_LOOKUP);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.lookup.name = name;
	fsdev_io->u_in.lookup.parent_fobject = parent_fobject;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_syncfs(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		  uint64_t unique, struct spdk_fsdev_file_object *fobject,
		  spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_SYNCFS);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.syncfs.fobject = fobject;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_access(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		  uint64_t unique, struct spdk_fsdev_file_object *fobject,
		  uint32_t mask, uid_t uid, uid_t gid, spdk_fsdev_cpl_cb cb_fn,
		  void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_ACCESS);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.access.fobject = fobject;
	fsdev_io->u_in.access.mask = mask;
	fsdev_io->u_in.access.uid = uid;
	fsdev_io->u_in.access.gid = gid;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_ioctl(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		 uint64_t unique, struct spdk_fsdev_file_object *fobject,
		 struct spdk_fsdev_file_handle *fhandle, uint32_t request,
		 uint64_t arg, struct iovec *in_iov, uint32_t in_iovcnt,
		 struct iovec *out_iov, uint32_t out_iovcnt,
		 spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_IOCTL);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.ioctl.fobject = fobject;
	fsdev_io->u_in.ioctl.fhandle = fhandle;
	fsdev_io->u_in.ioctl.request = request;
	fsdev_io->u_in.ioctl.arg = arg;

	fsdev_io->u_in.ioctl.in_iov = in_iov;
	fsdev_io->u_in.ioctl.in_iovcnt = in_iovcnt;

	fsdev_io->u_in.ioctl.out_iov = out_iov;
	fsdev_io->u_in.ioctl.out_iovcnt = out_iovcnt;

	/* Zero out the out values so we know what to free in _spdk_fsdev_ioctl_cb() */
	fsdev_io->u_out.ioctl.in_iov = NULL;
	fsdev_io->u_out.ioctl.in_iovcnt = 0;
	fsdev_io->u_out.ioctl.out_iov = NULL;
	fsdev_io->u_out.ioctl.out_iovcnt = 0;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_forget(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		  struct spdk_fsdev_file_object *fobject, uint64_t nlookup,
		  spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_FORGET);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.forget.fobject = fobject;
	fsdev_io->u_in.forget.nlookup = nlookup;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_getattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		   struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		   spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_GETATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.getattr.fobject = fobject;
	fsdev_io->u_in.getattr.fhandle = fhandle;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_setattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		   struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		   const struct spdk_fsdev_file_attr *attr, uint32_t to_set,
		   spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_SETATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.setattr.fobject = fobject;
	fsdev_io->u_in.setattr.fhandle = fhandle;
	fsdev_io->u_in.setattr.attr = *attr;
	fsdev_io->u_in.setattr.to_set = to_set;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_readlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    struct spdk_fsdev_file_object *fobject, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_READLINK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.readlink.fobject = fobject;
	fsdev_io->u_out.readlink.linkname = NULL;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_symlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		   struct spdk_fsdev_file_object *parent_fobject, const char *target, const char *linkpath,
		   uid_t euid, gid_t egid, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_SYMLINK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.symlink.target = target;
	fsdev_io->u_in.symlink.linkpath = linkpath;
	fsdev_io->u_in.symlink.parent_fobject = parent_fobject;
	fsdev_io->u_in.symlink.euid = euid;
	fsdev_io->u_in.symlink.egid = egid;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_getlk(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		 uint64_t unique, struct spdk_fsdev_file_object *fobject,
		 struct spdk_fsdev_file_handle *fhandle,
		 const struct spdk_fsdev_file_lock *lock_to_check,
		 uint64_t owner, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_GETLK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.getlk.fobject = fobject;
	fsdev_io->u_in.getlk.fhandle = fhandle;
	fsdev_io->u_in.getlk.lock = *lock_to_check;
	fsdev_io->u_in.getlk.owner = owner;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_setlk(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		 uint64_t unique, struct spdk_fsdev_file_object *fobject,
		 struct spdk_fsdev_file_handle *fhandle,
		 const struct spdk_fsdev_file_lock *lock_to_acquire,
		 uint64_t owner, bool wait, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_SETLK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.setlk.fobject = fobject;
	fsdev_io->u_in.setlk.fhandle = fhandle;
	fsdev_io->u_in.setlk.lock = *lock_to_acquire;
	fsdev_io->u_in.setlk.owner = owner;
	fsdev_io->u_in.setlk.wait = wait;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_mknod(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		 struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode, dev_t rdev,
		 uint32_t umask, uid_t euid, gid_t egid, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_MKNOD);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.mknod.name = name;
	fsdev_io->u_in.mknod.parent_fobject = parent_fobject;
	fsdev_io->u_in.mknod.mode = mode;
	fsdev_io->u_in.mknod.umask = umask;
	fsdev_io->u_in.mknod.rdev = rdev;
	fsdev_io->u_in.mknod.euid = euid;
	fsdev_io->u_in.mknod.egid = egid;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_mkdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		 struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode,
		 uint32_t umask, uid_t euid, gid_t egid, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_MKDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.mkdir.name = name;
	fsdev_io->u_in.mkdir.parent_fobject = parent_fobject;
	fsdev_io->u_in.mkdir.mode = mode;
	fsdev_io->u_in.mkdir.umask = umask;
	fsdev_io->u_in.mkdir.euid = euid;
	fsdev_io->u_in.mkdir.egid = egid;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_unlink(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		  struct spdk_fsdev_file_object *parent_fobject, const char *name,
		  spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_UNLINK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.unlink.name = name;
	fsdev_io->u_in.unlink.parent_fobject = parent_fobject;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_rmdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		 struct spdk_fsdev_file_object *parent_fobject, const char *name,
		 spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_RMDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.rmdir.name = name;
	fsdev_io->u_in.rmdir.parent_fobject = parent_fobject;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_rename(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		  struct spdk_fsdev_file_object *parent_fobject, const char *name,
		  struct spdk_fsdev_file_object *new_parent_fobject, const char *new_name,
		  uint32_t flags, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_RENAME);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.rename.name = name;
	fsdev_io->u_in.rename.new_name = new_name;
	fsdev_io->u_in.rename.parent_fobject = parent_fobject;
	fsdev_io->u_in.rename.new_parent_fobject = new_parent_fobject;
	fsdev_io->u_in.rename.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_link(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_object *new_parent_fobject,
		const char *name, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_LINK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.link.name = name;
	fsdev_io->u_in.link.fobject = fobject;
	fsdev_io->u_in.link.new_parent_fobject = new_parent_fobject;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_fopen(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		 struct spdk_fsdev_file_object *fobject, uint32_t flags,
		 spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_OPEN);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.open.fobject = fobject;
	fsdev_io->u_in.open.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_read(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		size_t size, uint64_t offs, uint32_t flags,
		struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_io_opts *opts,
		spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_READ);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.read.fobject = fobject;
	fsdev_io->u_in.read.fhandle = fhandle;
	fsdev_io->u_in.read.size = size;
	fsdev_io->u_in.read.offs = offs;
	fsdev_io->u_in.read.flags = flags;
	fsdev_io->u_in.read.iov = iov;
	fsdev_io->u_in.read.iovcnt = iovcnt;
	fsdev_io->u_in.read.opts = opts;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_write(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		 struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		 size_t size, uint64_t offs, uint64_t flags,
		 const struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_io_opts *opts,
		 spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_WRITE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.write.fobject = fobject;
	fsdev_io->u_in.write.fhandle = fhandle;
	fsdev_io->u_in.write.size = size;
	fsdev_io->u_in.write.offs = offs;
	fsdev_io->u_in.write.flags = flags;
	fsdev_io->u_in.write.iov = iov;
	fsdev_io->u_in.write.iovcnt = iovcnt;
	fsdev_io->u_in.write.opts = opts;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_statfs(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		  struct spdk_fsdev_file_object *fobject, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_STATFS);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.statfs.fobject = fobject;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_release(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		   struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		   spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_RELEASE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.release.fobject = fobject;
	fsdev_io->u_in.release.fhandle = fhandle;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_fsync(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		 struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle, bool datasync,
		 spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_FSYNC);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.fsync.fobject = fobject;
	fsdev_io->u_in.fsync.fhandle = fhandle;
	fsdev_io->u_in.fsync.datasync = datasync;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_setxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    struct spdk_fsdev_file_object *fobject, const char *name, const char *value, size_t size,
		    uint64_t flags, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_SETXATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.setxattr.name = name;
	fsdev_io->u_in.setxattr.value = value;
	fsdev_io->u_in.setxattr.fobject = fobject;
	fsdev_io->u_in.setxattr.size = size;
	fsdev_io->u_in.setxattr.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_getxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    struct spdk_fsdev_file_object *fobject, const char *name, void *buffer, size_t size,
		    spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_GETXATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.getxattr.name = name;
	fsdev_io->u_in.getxattr.fobject = fobject;
	fsdev_io->u_in.getxattr.buffer = buffer;
	fsdev_io->u_in.getxattr.size = size;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_listxattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *fobject, char *buffer, size_t size,
		     spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_LISTXATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.listxattr.fobject = fobject;
	fsdev_io->u_in.listxattr.buffer = buffer;
	fsdev_io->u_in.listxattr.size = size;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_removexattr(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		       struct spdk_fsdev_file_object *fobject, const char *name,
		       spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_REMOVEXATTR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.removexattr.name = name;
	fsdev_io->u_in.removexattr.fobject = fobject;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_flush(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		 struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		 spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_FLUSH);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.flush.fobject = fobject;
	fsdev_io->u_in.flush.fhandle = fhandle;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_opendir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		   struct spdk_fsdev_file_object *fobject, uint32_t flags,
		   spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_OPENDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.opendir.fobject = fobject;
	fsdev_io->u_in.opendir.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}

static int
_spdk_fsdev_readdir_entry_clb(struct spdk_fsdev_io *fsdev_io, void *cb_arg, bool *forget)
{
	spdk_fsdev_readdir_entry_cb *usr_entry_cb_fn = fsdev_io->u_in.readdir.usr_entry_cb_fn;
	return usr_entry_cb_fn(fsdev_io->internal.usr_cb_arg, fsdev_io->u_out.readdir.name,
			       fsdev_io->u_out.readdir.fobject, &fsdev_io->u_out.readdir.attr,
			       fsdev_io->u_out.readdir.offset, forget);
}

int
spdk_fsdev_readdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		   struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle, uint64_t offset,
		   spdk_fsdev_readdir_entry_cb entry_cb_fn, spdk_fsdev_cpl_cb cpl_cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cpl_cb_fn, cb_arg, SPDK_FSDEV_IO_READDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.readdir.fobject = fobject;
	fsdev_io->u_in.readdir.fhandle = fhandle;
	fsdev_io->u_in.readdir.offset = offset;
	fsdev_io->u_in.readdir.entry_cb_fn = _spdk_fsdev_readdir_entry_clb;
	fsdev_io->u_in.readdir.usr_entry_cb_fn = entry_cb_fn;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_releasedir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		      struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		      spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_RELEASEDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.releasedir.fobject = fobject;
	fsdev_io->u_in.releasedir.fhandle = fhandle;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_fsyncdir(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		    struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle, bool datasync,
		    spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_FSYNCDIR);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.fsyncdir.fobject = fobject;
	fsdev_io->u_in.fsyncdir.fhandle = fhandle;
	fsdev_io->u_in.fsyncdir.datasync = datasync;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_flock(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		 struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		 enum spdk_fsdev_file_lock_op operation, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_FLOCK);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.flock.fobject = fobject;
	fsdev_io->u_in.flock.fhandle = fhandle;
	fsdev_io->u_in.flock.operation = operation;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_create(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		  struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode, uint32_t flags,
		  mode_t umask, uid_t euid, gid_t egid, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_CREATE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.create.name = name;
	fsdev_io->u_in.create.parent_fobject = parent_fobject;
	fsdev_io->u_in.create.mode = mode;
	fsdev_io->u_in.create.flags = flags;
	fsdev_io->u_in.create.umask = umask;
	fsdev_io->u_in.create.euid = euid;
	fsdev_io->u_in.create.egid = egid;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_abort(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		 uint64_t unique_to_abort, spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, 0, cb_fn, cb_arg, SPDK_FSDEV_IO_ABORT);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.abort.unique_to_abort = unique_to_abort;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_fallocate(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch, uint64_t unique,
		     struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		     int mode, off_t offset, off_t length,
		     spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_FALLOCATE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.fallocate.fobject = fobject;
	fsdev_io->u_in.fallocate.fhandle = fhandle;
	fsdev_io->u_in.fallocate.mode = mode;
	fsdev_io->u_in.fallocate.offset = offset;
	fsdev_io->u_in.fallocate.length = length;

	fsdev_io_submit(fsdev_io);
	return 0;
}

int
spdk_fsdev_copy_file_range(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
			   uint64_t unique,
			   struct spdk_fsdev_file_object *fobject_in, struct spdk_fsdev_file_handle *fhandle_in, off_t off_in,
			   struct spdk_fsdev_file_object *fobject_out, struct spdk_fsdev_file_handle *fhandle_out,
			   off_t off_out, size_t len, uint32_t flags,
			   spdk_fsdev_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io;

	fsdev_io = fsdev_io_get_and_fill(desc, ch, unique, cb_fn, cb_arg, SPDK_FSDEV_IO_COPY_FILE_RANGE);
	if (!fsdev_io) {
		return -ENOBUFS;
	}

	fsdev_io->u_in.copy_file_range.fobject_in = fobject_in;
	fsdev_io->u_in.copy_file_range.fhandle_in = fhandle_in;
	fsdev_io->u_in.copy_file_range.off_in = off_in;
	fsdev_io->u_in.copy_file_range.fobject_out = fobject_out;
	fsdev_io->u_in.copy_file_range.fhandle_out = fhandle_out;
	fsdev_io->u_in.copy_file_range.off_out = off_out;
	fsdev_io->u_in.copy_file_range.len = len;
	fsdev_io->u_in.copy_file_range.flags = flags;

	fsdev_io_submit(fsdev_io);
	return 0;
}
