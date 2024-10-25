/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/*
 * This is a simple example of a virtual file system device module that passes IO
 * down to a fsdev (or fsdevs) that its configured to attach to.
 */

#include "spdk/stdinc.h"

#include "vfsdev_passthru.h"
#include "spdk/rpc.h"
#include "spdk/env.h"
#include "spdk/endian.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"

#include "spdk/fsdev_module.h"
#include "spdk/log.h"


static int vfsdev_passthru_init(void);
static int vfsdev_passthru_get_ctx_size(void);
static void vfsdev_passthru_finish(void);
static int vfsdev_passthru_config_json(struct spdk_json_write_ctx *w);

static struct spdk_fsdev_module passthru_if = {
	.name = "passthru_external",
	.module_init = vfsdev_passthru_init,
	.module_fini = vfsdev_passthru_finish,
	.config_json = vfsdev_passthru_config_json,
	.get_ctx_size = vfsdev_passthru_get_ctx_size
};

SPDK_FSDEV_MODULE_REGISTER(ext_passthru, &passthru_if)

/* List of passthru fsdev names and their base fsdevs via configuration file.
 * Used so we can parse the conf once at init and use this list in examine().
 */
struct passthru_associations {
	char			*passthru_name;
	char			*base_name;
	TAILQ_ENTRY(passthru_associations)	link;
};
static TAILQ_HEAD(, passthru_associations) g_passthru_associations = TAILQ_HEAD_INITIALIZER(
			g_passthru_associations);

/* List of virtual fsdevs and associated info for each. */
struct vfsdev_passthru {
	struct spdk_fsdev		*base_fsdev; /* the thing we're attaching to */
	struct spdk_fsdev_desc		*base_desc; /* its descriptor we get from open */
	struct spdk_fsdev		pt_fsdev;    /* the PT virtual fsdev */
	TAILQ_ENTRY(vfsdev_passthru)	link;
	struct spdk_thread		*thread;    /* thread where base device is opened */
};
static TAILQ_HEAD(, vfsdev_passthru) g_pt_nodes = TAILQ_HEAD_INITIALIZER(g_pt_nodes);

/* The pt vfsdev channel struct. It is allocated and freed on my behalf by the io channel code.
 * If this vfsdev needed to implement a poller or a queue for IO, this is where those things
 * would be defined. This passthru fsdev doesn't actually need to allocate a channel, it could
 * simply pass back the channel of the fsdev underneath it but for example purposes we will
 * present its own to the upper layers.
 */
struct pt_io_channel {
	struct spdk_io_channel	*base_ch; /* IO channel of base device */
};

/* This passthru_fsdev module doesn't need it but this is essentially a per IO
 * context that we get handed by the fsdev layer.
 */
struct passthru_fsdev_io {
	uint8_t test;
};

static void vfsdev_passthru_submit_request(struct spdk_io_channel *ch,
		struct spdk_fsdev_io *fsdev_io);


/* Callback for unregistering the IO device. */
static void
_device_unregister_cb(void *io_device)
{
	struct vfsdev_passthru *pt_node  = io_device;

	/* Done with this pt_node. */
	free(pt_node->pt_fsdev.name);
	free(pt_node);
}

/* Wrapper for the fsdev close operation. */
static void
_vfsdev_passthru_destruct(void *ctx)
{
	struct spdk_fsdev_desc *desc = ctx;

	spdk_fsdev_close(desc);
}

/* Called after we've unregistered following a hot remove callback.
 * Our finish entry point will be called next.
 */
static int
vfsdev_passthru_destruct(void *ctx)
{
	struct vfsdev_passthru *pt_node = (struct vfsdev_passthru *)ctx;

	/* It is important to follow this exact sequence of steps for destroying
	 * a vfsdev...
	 */
	TAILQ_REMOVE(&g_pt_nodes, pt_node, link);

	/* Close the underlying fsdev on its same opened thread. */
	if (pt_node->thread && pt_node->thread != spdk_get_thread()) {
		spdk_thread_send_msg(pt_node->thread, _vfsdev_passthru_destruct, pt_node->base_desc);
	} else {
		_vfsdev_passthru_destruct(pt_node->base_desc);
	}

	/* Unregister the io_device. */
	spdk_io_device_unregister(pt_node, _device_unregister_cb);

	return 0;
}

static void
vfsdev_passthru_check_io_ctx(struct spdk_fsdev_io *fsdev_io)
{
	struct passthru_fsdev_io *io_ctx = (struct passthru_fsdev_io *)fsdev_io->driver_ctx;

	/* We setup this value in the submission routine, just showing here that it is
	 * passed back to us.
	 */
	if (io_ctx->test != 0x5a) {
		SPDK_ERRLOG("Error, original IO device_ctx is wrong! 0x%x\n", io_ctx->test);
	}
}

static void
vfsdev_passthru_mount_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			     const struct spdk_fsdev_mount_opts *opts,
			     struct spdk_fsdev_file_object *root_fobject)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.mount.opts = *opts;
	fsdev_io->u_out.mount.root_fobject = root_fobject;
	spdk_fsdev_io_complete(fsdev_io, status);
}

static void
vfsdev_passthru_umount_cpl_cb(void *cb_arg, struct spdk_io_channel *ch)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	spdk_fsdev_io_complete(cb_arg, 0);
}

static void
vfsdev_passthru_status_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	spdk_fsdev_io_complete(cb_arg, status);
}

#define CPL_CB_FOBJECT_ATTR(io_type) \
static void \
vfsdev_passthru_ ## io_type ## _cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status, \
				       struct spdk_fsdev_file_object *fobject, \
				       const struct spdk_fsdev_file_attr *attr) \
{ \
	struct spdk_fsdev_io *fsdev_io = cb_arg; \
	vfsdev_passthru_check_io_ctx(fsdev_io); \
	fsdev_io->u_out.io_type.fobject = fobject; \
	fsdev_io->u_out.io_type.attr = *attr; \
	spdk_fsdev_io_complete(fsdev_io, status); \
}

CPL_CB_FOBJECT_ATTR(lookup)
CPL_CB_FOBJECT_ATTR(mknod)
CPL_CB_FOBJECT_ATTR(symlink)
CPL_CB_FOBJECT_ATTR(mkdir)
CPL_CB_FOBJECT_ATTR(link)

#define CPL_CB_DATA_SIZE(io_type) \
static void \
vfsdev_passthru_ ## io_type ## _cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status, uint32_t data_size) \
{ \
	struct spdk_fsdev_io *fsdev_io = cb_arg; \
	vfsdev_passthru_check_io_ctx(fsdev_io); \
	fsdev_io->u_out.io_type.data_size = data_size; \
	spdk_fsdev_io_complete(fsdev_io, status); \
}

CPL_CB_DATA_SIZE(read)
CPL_CB_DATA_SIZE(write)
CPL_CB_DATA_SIZE(copy_file_range)

#define CPL_CB_ATTR(io_type) \
static void \
vfsdev_passthru_ ## io_type ## _cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status, \
				       const struct spdk_fsdev_file_attr *attr) \
{ \
	struct spdk_fsdev_io *fsdev_io = cb_arg; \
	vfsdev_passthru_check_io_ctx(fsdev_io); \
	fsdev_io->u_out.io_type.attr = *attr; \
	spdk_fsdev_io_complete(cb_arg, status); \
}

CPL_CB_ATTR(getattr)
CPL_CB_ATTR(setattr)

#define CPL_CB_FHANDLE(io_type) \
static void \
vfsdev_passthru_ ## io_type ## _cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status, \
				       struct spdk_fsdev_file_handle *fhandle) \
{ \
	struct spdk_fsdev_io *fsdev_io = cb_arg; \
	vfsdev_passthru_check_io_ctx(fsdev_io); \
	fsdev_io->u_out.io_type.fhandle = fhandle; \
	spdk_fsdev_io_complete(fsdev_io, status); \
}

CPL_CB_FHANDLE(open)
CPL_CB_FHANDLE(opendir)

static void
vfsdev_passthru_readlink_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
				const char *linkname)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.readlink.linkname = strdup(linkname);
	spdk_fsdev_io_complete(cb_arg, status);
}

static void
vfsdev_passthru_statfs_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			      const struct spdk_fsdev_file_statfs *statfs)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.statfs.statfs = *statfs;
	spdk_fsdev_io_complete(cb_arg, status);
}

static void
vfsdev_passthru_getxattr_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
				size_t value_size)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.getxattr.value_size = value_size;
	spdk_fsdev_io_complete(cb_arg, status);
}

static void
vfsdev_passthru_listxattr_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
				 size_t size, bool size_only)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.listxattr.data_size = size;
	fsdev_io->u_out.listxattr.size_only = size_only;
	spdk_fsdev_io_complete(cb_arg, status);
}

static void
vfsdev_passthru_create_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			      struct spdk_fsdev_file_object *fobject,
			      const struct spdk_fsdev_file_attr *attr,
			      struct spdk_fsdev_file_handle *fhandle)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.create.fobject = fobject;
	fsdev_io->u_out.create.attr = *attr;
	fsdev_io->u_out.create.fhandle = fhandle;
	spdk_fsdev_io_complete(cb_arg, status);
}

static void
vfsdev_passthru_access_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			      uint32_t mask, uid_t uid, uid_t gid)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.access.mask = mask;
	fsdev_io->u_out.access.uid = uid;
	fsdev_io->u_out.access.gid = gid;
	spdk_fsdev_io_complete(cb_arg, status);
}

static void
vfsdev_passthru_lseek_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			     off_t offset, enum spdk_fsdev_seek_whence whence)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.lseek.offset = offset;
	fsdev_io->u_out.lseek.whence = whence;
	spdk_fsdev_io_complete(cb_arg, status);
}

static void
vfsdev_passthru_poll_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			    uint32_t revents)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.poll.revents = revents;
	spdk_fsdev_io_complete(cb_arg, status);
}

static void
vfsdev_passthru_ioctl_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			     int32_t result,
			     struct iovec *in_iov, uint32_t in_iovcnt,
			     struct iovec *out_iov, uint32_t out_iovcnt)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.ioctl.result = result;
	fsdev_io->u_out.ioctl.in_iov = in_iov;
	fsdev_io->u_out.ioctl.in_iovcnt = in_iovcnt;
	fsdev_io->u_out.ioctl.out_iov = out_iov;
	fsdev_io->u_out.ioctl.out_iovcnt = out_iovcnt;
	spdk_fsdev_io_complete(cb_arg, status);
}

static void
vfsdev_passthru_getlk_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			     const struct spdk_fsdev_file_lock *lock)
{
	struct spdk_fsdev_io *fsdev_io = cb_arg;

	vfsdev_passthru_check_io_ctx(fsdev_io);
	fsdev_io->u_out.getlk.lock = *lock;
	spdk_fsdev_io_complete(cb_arg, status);
}

/* Called when someone above submits IO to this pt vfsdev. We're simply passing it on here
 * via SPDK IO calls which in turn allocate another fsdev IO and call our cpl callback provided
 * below along with the original fsdev_io so that we can complete it once this IO completes.
 */
static void
vfsdev_passthru_submit_request(struct spdk_io_channel *ch, struct spdk_fsdev_io *fsdev_io)
{
	struct vfsdev_passthru *pt_node = SPDK_CONTAINEROF(fsdev_io->fsdev, struct vfsdev_passthru,
					  pt_fsdev);
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	struct passthru_fsdev_io *io_ctx = (struct passthru_fsdev_io *)fsdev_io->driver_ctx;
	enum spdk_fsdev_io_type type = spdk_fsdev_io_get_type(fsdev_io);
	int rc = 0;

	/* Setup a per IO context value; we don't do anything with it in the vfsdev other
	 * than confirm we get the same thing back in the completion callback just to
	 * demonstrate.
	 */
	io_ctx->test = 0x5a;

	switch (type) {
	case SPDK_FSDEV_IO_MOUNT:
		rc = spdk_fsdev_mount(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      &fsdev_io->u_in.mount.opts,
				      vfsdev_passthru_mount_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_UMOUNT:
		rc = spdk_fsdev_umount(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				       vfsdev_passthru_umount_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_LOOKUP:
		rc = spdk_fsdev_lookup(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				       fsdev_io->u_in.lookup.parent_fobject,
				       fsdev_io->u_in.lookup.name,
				       vfsdev_passthru_lookup_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_FORGET:
		rc = spdk_fsdev_forget(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				       fsdev_io->u_in.forget.fobject,
				       fsdev_io->u_in.forget.nlookup,
				       vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_MKNOD:
		rc = spdk_fsdev_mknod(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.mknod.parent_fobject,
				      fsdev_io->u_in.mknod.name,
				      fsdev_io->u_in.mknod.mode,
				      fsdev_io->u_in.mknod.rdev,
				      fsdev_io->u_in.mknod.umask,
				      fsdev_io->u_in.mknod.euid,
				      fsdev_io->u_in.mknod.egid,
				      vfsdev_passthru_mknod_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_OPEN:
		rc = spdk_fsdev_fopen(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.open.fobject,
				      fsdev_io->u_in.open.flags,
				      vfsdev_passthru_open_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_WRITE:
		rc = spdk_fsdev_write(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.write.fobject,
				      fsdev_io->u_in.write.fhandle,
				      fsdev_io->u_in.write.size,
				      fsdev_io->u_in.write.offs,
				      fsdev_io->u_in.write.flags,
				      fsdev_io->u_in.write.iov,
				      fsdev_io->u_in.write.iovcnt,
				      fsdev_io->u_in.write.opts,
				      vfsdev_passthru_write_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_READ:
		rc = spdk_fsdev_read(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				     fsdev_io->u_in.read.fobject,
				     fsdev_io->u_in.read.fhandle,
				     fsdev_io->u_in.read.size,
				     fsdev_io->u_in.read.offs,
				     fsdev_io->u_in.read.flags,
				     fsdev_io->u_in.read.iov,
				     fsdev_io->u_in.read.iovcnt,
				     fsdev_io->u_in.read.opts,
				     vfsdev_passthru_read_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_RELEASE:
		rc = spdk_fsdev_release(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					fsdev_io->u_in.release.fobject,
					fsdev_io->u_in.release.fhandle,
					vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_UNLINK:
		rc = spdk_fsdev_unlink(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				       fsdev_io->u_in.unlink.parent_fobject,
				       fsdev_io->u_in.unlink.name,
				       vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_GETATTR:
		rc = spdk_fsdev_getattr(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					fsdev_io->u_in.getattr.fobject,
					fsdev_io->u_in.getattr.fhandle,
					vfsdev_passthru_getattr_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_SETATTR:
		rc = spdk_fsdev_setattr(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					fsdev_io->u_in.setattr.fobject,
					fsdev_io->u_in.setattr.fhandle,
					&fsdev_io->u_in.setattr.attr,
					fsdev_io->u_in.setattr.to_set,
					vfsdev_passthru_setattr_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_READLINK:
		rc = spdk_fsdev_readlink(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					 fsdev_io->u_in.readlink.fobject,
					 vfsdev_passthru_readlink_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_SYMLINK:
		rc = spdk_fsdev_symlink(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					fsdev_io->u_in.symlink.parent_fobject,
					fsdev_io->u_in.symlink.target,
					fsdev_io->u_in.symlink.linkpath,
					fsdev_io->u_in.symlink.euid,
					fsdev_io->u_in.symlink.egid,
					vfsdev_passthru_symlink_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_MKDIR:
		rc = spdk_fsdev_mkdir(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.mkdir.parent_fobject,
				      fsdev_io->u_in.mkdir.name,
				      fsdev_io->u_in.mkdir.mode,
				      fsdev_io->u_in.mkdir.umask,
				      fsdev_io->u_in.mkdir.euid,
				      fsdev_io->u_in.mkdir.egid,
				      vfsdev_passthru_mkdir_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_RMDIR:
		rc = spdk_fsdev_rmdir(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.rmdir.parent_fobject,
				      fsdev_io->u_in.rmdir.name,
				      vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_RENAME:
		rc = spdk_fsdev_rename(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				       fsdev_io->u_in.rename.parent_fobject,
				       fsdev_io->u_in.rename.name,
				       fsdev_io->u_in.rename.new_parent_fobject,
				       fsdev_io->u_in.rename.new_name,
				       fsdev_io->u_in.rename.flags,
				       vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_LINK:
		rc = spdk_fsdev_link(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				     fsdev_io->u_in.link.fobject,
				     fsdev_io->u_in.link.new_parent_fobject,
				     fsdev_io->u_in.link.name,
				     vfsdev_passthru_link_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_STATFS:
		rc = spdk_fsdev_statfs(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				       fsdev_io->u_in.statfs.fobject,
				       vfsdev_passthru_statfs_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_FSYNC:
		rc = spdk_fsdev_fsync(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.fsync.fobject,
				      fsdev_io->u_in.fsync.fhandle,
				      fsdev_io->u_in.fsync.datasync,
				      vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_SETXATTR:
		rc = spdk_fsdev_setxattr(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					 fsdev_io->u_in.setxattr.fobject,
					 fsdev_io->u_in.setxattr.name,
					 fsdev_io->u_in.setxattr.value,
					 fsdev_io->u_in.setxattr.size,
					 fsdev_io->u_in.setxattr.flags,
					 vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_GETXATTR:
		rc = spdk_fsdev_getxattr(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					 fsdev_io->u_in.getxattr.fobject,
					 fsdev_io->u_in.getxattr.name,
					 fsdev_io->u_in.getxattr.buffer,
					 fsdev_io->u_in.getxattr.size,
					 vfsdev_passthru_getxattr_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_LISTXATTR:
		rc = spdk_fsdev_listxattr(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					  fsdev_io->u_in.listxattr.fobject,
					  fsdev_io->u_in.listxattr.buffer,
					  fsdev_io->u_in.listxattr.size,
					  vfsdev_passthru_listxattr_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_REMOVEXATTR:
		rc = spdk_fsdev_removexattr(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					    fsdev_io->u_in.removexattr.fobject,
					    fsdev_io->u_in.removexattr.name,
					    vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_FLUSH:
		rc = spdk_fsdev_flush(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.flush.fobject,
				      fsdev_io->u_in.flush.fhandle,
				      vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_OPENDIR:
		rc = spdk_fsdev_opendir(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					fsdev_io->u_in.opendir.fobject,
					fsdev_io->u_in.opendir.flags,
					vfsdev_passthru_opendir_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_READDIR:
		rc = spdk_fsdev_readdir(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					fsdev_io->u_in.readdir.fobject,
					fsdev_io->u_in.readdir.fhandle,
					fsdev_io->u_in.readdir.offset,
					fsdev_io->u_in.readdir.usr_entry_cb_fn,
					vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_RELEASEDIR:
		rc = spdk_fsdev_releasedir(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					   fsdev_io->u_in.releasedir.fobject,
					   fsdev_io->u_in.releasedir.fhandle,
					   vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_FSYNCDIR:
		rc = spdk_fsdev_fsyncdir(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					 fsdev_io->u_in.fsyncdir.fobject,
					 fsdev_io->u_in.fsyncdir.fhandle,
					 fsdev_io->u_in.fsyncdir.datasync,
					 vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_FLOCK:
		rc = spdk_fsdev_flock(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.flock.fobject,
				      fsdev_io->u_in.flock.fhandle,
				      fsdev_io->u_in.flock.operation,
				      vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_CREATE:
		rc = spdk_fsdev_create(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				       fsdev_io->u_in.create.parent_fobject,
				       fsdev_io->u_in.create.name,
				       fsdev_io->u_in.create.mode,
				       fsdev_io->u_in.create.flags,
				       fsdev_io->u_in.create.umask,
				       fsdev_io->u_in.create.euid,
				       fsdev_io->u_in.create.egid,
				       vfsdev_passthru_create_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_ABORT:
		rc = spdk_fsdev_abort(pt_node->base_desc, pt_ch->base_ch,
				      fsdev_io->u_in.abort.unique_to_abort,
				      vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_FALLOCATE:
		rc = spdk_fsdev_fallocate(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
					  fsdev_io->u_in.fallocate.fobject,
					  fsdev_io->u_in.fallocate.fhandle,
					  fsdev_io->u_in.fallocate.mode,
					  fsdev_io->u_in.fallocate.offset,
					  fsdev_io->u_in.fallocate.length,
					  vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_COPY_FILE_RANGE:
		rc = spdk_fsdev_copy_file_range(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
						fsdev_io->u_in.copy_file_range.fobject_in,
						fsdev_io->u_in.copy_file_range.fhandle_in,
						fsdev_io->u_in.copy_file_range.off_in,
						fsdev_io->u_in.copy_file_range.fobject_out,
						fsdev_io->u_in.copy_file_range.fhandle_out,
						fsdev_io->u_in.copy_file_range.off_out,
						fsdev_io->u_in.copy_file_range.len,
						fsdev_io->u_in.copy_file_range.flags,
						vfsdev_passthru_copy_file_range_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_SYNCFS:
		rc = spdk_fsdev_syncfs(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				       fsdev_io->u_in.syncfs.fobject,
				       vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_ACCESS:
		rc = spdk_fsdev_access(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				       fsdev_io->u_in.access.fobject,
				       fsdev_io->u_in.access.mask,
				       fsdev_io->u_in.access.uid,
				       fsdev_io->u_in.access.gid,
				       vfsdev_passthru_access_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_LSEEK:
		rc = spdk_fsdev_lseek(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.lseek.fobject,
				      fsdev_io->u_in.lseek.fhandle,
				      fsdev_io->u_in.lseek.offset,
				      fsdev_io->u_in.lseek.whence,
				      vfsdev_passthru_lseek_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_POLL:
		rc = spdk_fsdev_poll(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				     fsdev_io->u_in.poll.fobject,
				     fsdev_io->u_in.poll.fhandle,
				     fsdev_io->u_in.poll.events,
				     fsdev_io->u_in.poll.wait,
				     vfsdev_passthru_poll_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_IOCTL:
		rc = spdk_fsdev_ioctl(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.ioctl.fobject,
				      fsdev_io->u_in.ioctl.fhandle,
				      fsdev_io->u_in.ioctl.request,
				      fsdev_io->u_in.ioctl.arg,
				      fsdev_io->u_in.ioctl.in_iov,
				      fsdev_io->u_in.ioctl.in_iovcnt,
				      fsdev_io->u_in.ioctl.out_iov,
				      fsdev_io->u_in.ioctl.out_iovcnt,
				      vfsdev_passthru_ioctl_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_GETLK:
		rc = spdk_fsdev_getlk(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.getlk.fobject,
				      fsdev_io->u_in.getlk.fhandle,
				      &fsdev_io->u_in.getlk.lock,
				      fsdev_io->u_in.getlk.owner,
				      vfsdev_passthru_getlk_cpl_cb, fsdev_io);
		break;
	case SPDK_FSDEV_IO_SETLK:
		rc = spdk_fsdev_setlk(pt_node->base_desc, pt_ch->base_ch, fsdev_io->internal.unique,
				      fsdev_io->u_in.setlk.fobject,
				      fsdev_io->u_in.setlk.fhandle,
				      &fsdev_io->u_in.setlk.lock,
				      fsdev_io->u_in.setlk.owner,
				      fsdev_io->u_in.setlk.wait,
				      vfsdev_passthru_status_cpl_cb, fsdev_io);
		break;
	default:
		SPDK_ERRLOG("passthru: unknown I/O type %d\n", type);
		spdk_fsdev_io_complete(fsdev_io, -ENOSYS);
		return;
	}

	if (rc != 0) {
		SPDK_ERRLOG("ERROR on fsdev_io submission!\n");
		spdk_fsdev_io_complete(fsdev_io, rc);
	}
}

/* We supplied this as an entry point for upper layers who want to communicate to this
 * fsdev.  This is how they get a channel. We are passed the same context we provided when
 * we created our PT vfsdev in examine() which, for this fsdev, is the address of one of
 * our context nodes. From here we'll ask the SPDK channel code to fill out our channel
 * struct and we'll keep it in our PT node.
 */
static struct spdk_io_channel *
vfsdev_passthru_get_io_channel(void *ctx)
{
	struct vfsdev_passthru *pt_node = (struct vfsdev_passthru *)ctx;
	struct spdk_io_channel *pt_ch = NULL;

	/* The IO channel code will allocate a channel for us which consists of
	 * the SPDK channel structure plus the size of our pt_io_channel struct
	 * that we passed in when we registered our IO device. It will then call
	 * our channel create callback to populate any elements that we need to
	 * update.
	 */
	pt_ch = spdk_get_io_channel(pt_node);

	return pt_ch;
}

struct vfsdev_passthru_reset_ctx {
	spdk_fsdev_reset_done_cb cb;
	void *cb_arg;
};

static void
vfsdev_passthru_reset_completion_cb(struct spdk_fsdev_desc *desc, bool success, void *cb_arg)
{
	struct vfsdev_passthru_reset_ctx *reset_ctx = (struct vfsdev_passthru_reset_ctx *)cb_arg;

	reset_ctx->cb(reset_ctx->cb_arg, success ? 0 : -1);
	free(reset_ctx);
}

static int
vfsdev_passthru_reset(void *ctx, spdk_fsdev_reset_done_cb cb, void *cb_arg)
{
	struct vfsdev_passthru *pt_node = (struct vfsdev_passthru *)ctx;
	struct vfsdev_passthru_reset_ctx *reset_ctx;

	reset_ctx = (struct vfsdev_passthru_reset_ctx *)malloc(sizeof(*reset_ctx));
	if (!reset_ctx) {
		SPDK_ERRLOG("No memory to allocate reset context.\n");
		return -ENOMEM;
	}

	reset_ctx->cb = cb;
	reset_ctx->cb_arg = cb_arg;
	return spdk_fsdev_reset(pt_node->base_desc, vfsdev_passthru_reset_completion_cb, reset_ctx);
}

/* This is the output for fsdev_get_fsdevs() for this vfsdev */
static int
vfsdev_passthru_dump_info_json(void *ctx, struct spdk_json_write_ctx *w)
{
	struct vfsdev_passthru *pt_node = (struct vfsdev_passthru *)ctx;

	spdk_json_write_name(w, "passthru_external");
	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "name", spdk_fsdev_get_name(&pt_node->pt_fsdev));
	spdk_json_write_named_string(w, "base_fsdev_name", spdk_fsdev_get_name(pt_node->base_fsdev));
	spdk_json_write_object_end(w);

	return 0;
}

/* This is used to generate JSON that can configure this module to its current state. */
static int
vfsdev_passthru_config_json(struct spdk_json_write_ctx *w)
{
	struct vfsdev_passthru *pt_node;

	TAILQ_FOREACH(pt_node, &g_pt_nodes, link) {
		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "method", "construct_ext_passthru_fsdev");
		spdk_json_write_named_object_begin(w, "params");
		spdk_json_write_named_string(w, "base_fsdev_name", spdk_fsdev_get_name(pt_node->base_fsdev));
		spdk_json_write_named_string(w, "name", spdk_fsdev_get_name(&pt_node->pt_fsdev));
		spdk_json_write_object_end(w);
		spdk_json_write_object_end(w);
	}
	return 0;
}

/* We provide this callback for the SPDK channel code to create a channel using
 * the channel struct we provided in our module get_io_channel() entry point. Here
 * we get and save off an underlying base channel of the device below us so that
 * we can communicate with the base fsdev on a per channel basis.  If we needed
 * our own poller for this vfsdev, we'd register it here.
 */
static int
pt_fsdev_ch_create_cb(void *io_device, void *ctx_buf)
{
	struct pt_io_channel *pt_ch = ctx_buf;
	struct vfsdev_passthru *pt_node = io_device;

	pt_ch->base_ch = spdk_fsdev_get_io_channel(pt_node->base_desc);

	return 0;
}

/* We provide this callback for the SPDK channel code to destroy a channel
 * created with our create callback. We just need to undo anything we did
 * when we created. If this fsdev used its own poller, we'd unregister it here.
 */
static void
pt_fsdev_ch_destroy_cb(void *io_device, void *ctx_buf)
{
	struct pt_io_channel *pt_ch = ctx_buf;

	spdk_put_io_channel(pt_ch->base_ch);
}

/* Create the passthru association from the base fsdev and passthru fsdev name and insert
 * on the global list. */
static int
vfsdev_passthru_insert_name(const char *base_name, const char *passthru_name)
{
	struct passthru_associations *assoc;

	TAILQ_FOREACH(assoc, &g_passthru_associations, link) {
		if (strcmp(passthru_name, assoc->passthru_name) == 0) {
			SPDK_ERRLOG("passthru fsdev %s already exists\n", passthru_name);
			return -EEXIST;
		}
	}

	assoc = calloc(1, sizeof(struct passthru_associations));
	if (!assoc) {
		SPDK_ERRLOG("could not allocate passthru_associations\n");
		return -ENOMEM;
	}

	assoc->base_name = strdup(base_name);
	if (!assoc->base_name) {
		SPDK_ERRLOG("could not allocate assoc->base_name\n");
		free(assoc);
		return -ENOMEM;
	}

	assoc->passthru_name = strdup(passthru_name);
	if (!assoc->passthru_name) {
		SPDK_ERRLOG("could not allocate assoc->passthru_name\n");
		free(assoc->base_name);
		free(assoc);
		return -ENOMEM;
	}

	TAILQ_INSERT_TAIL(&g_passthru_associations, assoc, link);

	return 0;
}

/* On init, just perform fsdev module specific initialization. */
static int
vfsdev_passthru_init(void)
{
	return 0;
}

/* Called when the entire module is being torn down. */
static void
vfsdev_passthru_finish(void)
{
	struct passthru_associations *assoc;

	while ((assoc = TAILQ_FIRST(&g_passthru_associations))) {
		TAILQ_REMOVE(&g_passthru_associations, assoc, link);
		free(assoc->base_name);
		free(assoc->passthru_name);
		free(assoc);
	}
}

/* During init we'll be asked how much memory we'd like passed to us
 * in fsdev_io structures as context. Here's where we specify how
 * much context we want per IO.
 */
static int
vfsdev_passthru_get_ctx_size(void)
{
	return sizeof(struct passthru_fsdev_io);
}

/* Where vfsdev_passthru_config_json() is used to generate per module JSON config data, this
 * function is called to output any per fsdev specific methods. For the PT module, there are
 * none.
 */
static void
vfsdev_passthru_write_config_json(struct spdk_fsdev *fsdev, struct spdk_json_write_ctx *w)
{
	/* No config per fsdev needed */
}

/* When we register our fsdev this is how we specify our entry points. */
static const struct spdk_fsdev_fn_table vfsdev_passthru_fn_table = {
	.destruct		= vfsdev_passthru_destruct,
	.submit_request		= vfsdev_passthru_submit_request,
	.get_io_channel		= vfsdev_passthru_get_io_channel,
	.write_config_json	= vfsdev_passthru_write_config_json,
	.reset			= vfsdev_passthru_reset,
	.dump_info_json		= vfsdev_passthru_dump_info_json
};

static void
vfsdev_passthru_base_fsdev_hotremove_cb(struct spdk_fsdev *fsdev_find)
{
	struct vfsdev_passthru *pt_node, *tmp;

	TAILQ_FOREACH_SAFE(pt_node, &g_pt_nodes, link, tmp) {
		if (fsdev_find == pt_node->base_fsdev) {
			spdk_fsdev_unregister(&pt_node->pt_fsdev, NULL, NULL);
		}
	}
}

/* Called when the underlying base fsdev triggers asynchronous event such as fsdev removal. */
static void
vfsdev_passthru_base_fsdev_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev,
				    void *event_ctx)
{
	switch (type) {
	case SPDK_FSDEV_EVENT_REMOVE:
		vfsdev_passthru_base_fsdev_hotremove_cb(fsdev);
		break;
	default:
		SPDK_NOTICELOG("Unsupported fsdev event: type %d\n", type);
		break;
	}
}

/* Create and register the passthru vfsdev if we find it in our list of fsdev names.
 * This can be called either by the examine path or RPC method.
 */
static int
vfsdev_passthru_register(const char *base_name)
{
	struct passthru_associations *assoc;
	struct vfsdev_passthru *pt_node;
	struct spdk_fsdev *fsdev;
	int rc = 0;

	/* Check our list of associations from config versus this fsdev and if
	 * there's a match, create the pt_node & fsdev accordingly.
	 */
	TAILQ_FOREACH(assoc, &g_passthru_associations, link) {
		if (strcmp(assoc->base_name, base_name) != 0) {
			continue;
		}

		SPDK_NOTICELOG("Match on %s\n", base_name);
		pt_node = calloc(1, sizeof(struct vfsdev_passthru));
		if (!pt_node) {
			rc = -ENOMEM;
			SPDK_ERRLOG("could not allocate pt_node\n");
			break;
		}

		pt_node->pt_fsdev.name = strdup(assoc->passthru_name);
		if (!pt_node->pt_fsdev.name) {
			rc = -ENOMEM;
			SPDK_ERRLOG("could not allocate pt_fsdev name\n");
			free(pt_node);
			break;
		}

		/* The base fsdev that we're attaching to. */
		rc = spdk_fsdev_open(base_name, vfsdev_passthru_base_fsdev_event_cb,
				     NULL, &pt_node->base_desc);
		if (rc) {
			if (rc != -ENODEV) {
				SPDK_ERRLOG("could not open fsdev %s\n", base_name);
			}
			free(pt_node->pt_fsdev.name);
			free(pt_node);
			break;
		}
		SPDK_NOTICELOG("base fsdev opened\n");

		fsdev = spdk_fsdev_desc_get_fsdev(pt_node->base_desc);
		pt_node->base_fsdev = fsdev;

		/* This is the context that is passed to us when the fsdev
		 * layer calls in so we'll save our pt_fsdev node here.
		 */
		pt_node->pt_fsdev.ctxt = pt_node;
		pt_node->pt_fsdev.fn_table = &vfsdev_passthru_fn_table;
		pt_node->pt_fsdev.module = &passthru_if;
		TAILQ_INSERT_TAIL(&g_pt_nodes, pt_node, link);

		spdk_io_device_register(pt_node, pt_fsdev_ch_create_cb, pt_fsdev_ch_destroy_cb,
					sizeof(struct pt_io_channel),
					assoc->passthru_name);
		SPDK_NOTICELOG("io_device created at: 0x%p\n", pt_node);

		/* Save the thread where the base device is opened */
		pt_node->thread = spdk_get_thread();

		rc = spdk_fsdev_register(&pt_node->pt_fsdev);
		if (rc) {
			SPDK_ERRLOG("could not register pt_fsdev\n");
			spdk_fsdev_close(pt_node->base_desc);
			TAILQ_REMOVE(&g_pt_nodes, pt_node, link);
			spdk_io_device_unregister(pt_node, NULL);
			free(pt_node->pt_fsdev.name);
			free(pt_node);
			break;
		}
		SPDK_NOTICELOG("ext_pt_fsdev registered\n");
		SPDK_NOTICELOG("created ext_pt_fsdev for: %s\n", assoc->passthru_name);
	}

	return rc;
}

/* Create the passthru fsdev from the given fsdev and vfsdev name. */
int
fsdev_passthru_external_create(const char *fsdev_name, const char *vfsdev_name)
{
	int rc;

	/* Insert the fsdev name into our global name list even if it doesn't exist yet,
	 * it may show up soon...
	 */
	rc = vfsdev_passthru_insert_name(fsdev_name, vfsdev_name);
	if (rc) {
		return rc;
	}

	rc = vfsdev_passthru_register(fsdev_name);
	if (rc == -ENODEV) {
		/* This is not an error, we tracked the name above and it still
		 * may show up later.
		 */
		SPDK_NOTICELOG("vfsdev creation deferred pending base fsdev arrival\n");
		rc = 0;
	}

	return rc;
}

void
fsdev_passthru_external_delete(const char *fsdev_name, spdk_fsdev_unregister_cb cb_fn,
			       void *cb_arg)
{
	struct passthru_associations *assoc;
	int rc;

	rc = spdk_fsdev_unregister_by_name(fsdev_name, &passthru_if, cb_fn, cb_arg);
	if (rc != 0) {
		cb_fn(cb_arg, rc);
		return;
	}

	/* Remove the association (passthru, base) from g_passthru_associations. This is required so that the
	 * passthru fsdev does not get re-created if the same base fsdev is constructed at some other time,
	 * unless the underlying fsdev was hot-removed.
	 */
	TAILQ_FOREACH(assoc, &g_passthru_associations, link) {
		if (strcmp(assoc->passthru_name, fsdev_name) == 0) {
			TAILQ_REMOVE(&g_passthru_associations, assoc, link);
			free(assoc->base_name);
			free(assoc->passthru_name);
			free(assoc);
			break;
		}
	}
}
