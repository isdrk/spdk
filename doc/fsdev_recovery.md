# Recovery {#recovery}

## In this document {#recovery_toc}

* @ref rmem

## Recovery Memory abstraction {#rmem}

The rmem abstraction is designed to allow hot recovery, for example, in case of application crash.

It allows the SPDK components to store some information in runtime and then recover it, if needed. For example,
upon the next invocation of the same application.

For more information, see the [spdk/rmem.h](../include/spdk/rmem.h).
