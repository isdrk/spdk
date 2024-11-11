# Recovery {#recovery}

## In this document {#recovery_toc}

* @ref rmem
* @ref fsdev_recovery
* @ref fuse_dispatcher_recovery

## Recovery Memory abstraction {#rmem}

The rmem abstraction is designed to allow hot recovery, for example, in case of application crash.

It allows the SPDK components to store some information in runtime and then recover it, if needed. For example,
upon the next invocation of the same application.

For more information, see the [spdk/rmem.h](../include/spdk/rmem.h).

## fsdev recovery {#fsdev_recovery}

An fsdev module might support recovery. The fsdev module that supports recovery:

* exposes `is_recovered` callback
* acts as any normal SPDK component that supports recovery (see [spdk/rmem.h](../include/spdk/rmem.h) for more details)
* upon fsdev creation (via a fsdev-module specific RPC or an API call):
  * checks whether the rmem functionality is enabled (`spdk_rmem_is_enabled`)
  * if so:
    * recovers rmem_pool(s) used by the fsdev module (`spdk_rmem_pool_restore`)
    * rebuild the fsdev's internal data structure based on the recovered data
    * if failed to recover - fails the fsdev creation
  * if not:
    * creates the rmem_pool(s) used by the fsdev module (`spdk_rmem_pool_create`)
  * during the fsdev lifetime, saves the data needed for the recovery using the `spdk_rmem_pool_get` and `spdk_rmem_entry_write` APIs
  * destroys (`spdk_rmem_pool_destroy`) the rmem_pool(s) used by the fsdev module upon the fsdev deletion
* makes the `is_recovered` callback return true if the fsdev state has been restored, false otherwise

## FUSE dispatcher recovery {#fuse_dispatcher_recovery}

The FUSE dispatcher supports the recovery.

The FUSE dispatcher recovery is controlled by the `recovery_mode` param of the `spdk_fuse_dispatcher_create` API.
If `recovery_mode` == `true`, the FUSE dispatcher will attempt to restore its state and will not fallback to the normal creation in case of failure.

An application that uses FUSE dispatcher and supports recovery would probably act along the following lines:

* enable the rmem functionality (`spdk_rmem_enable`) if needed
* create a desired fsdev
* check if the fsdev has been recovered (`spdk_fsdev_is_recovered`)
* if the fsdev has been recovered, call the `spdk_fuse_dispatcher_create` with `recovery_mode` == `true`, so both are recovered
* otherwise, call the `spdk_fuse_dispatcher_create` with `recovery_mode` == `false`, so both are created
