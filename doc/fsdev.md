# Filesystem Device User Guide {#fsdev}

## Introduction {#fsdev_introduction}

The fsdev library is intended to provide an interface for accessing filesystems, similar to Linux's
FUSE API.  It's inspired by and has a very similar architecture to the SPDK block device layer.  It
also has a pluggable module API allowing users to implement their own filesystems.  The interface
for application developers consuming the fsdev API is defined in `include/spdk/fsdev.h`, while the
code for people writing fsdev modules can be found in `include/spdk/fsdev_module.h`.  Currently, the
only available fsdev module is @ref fsdev_aio.

## FUSE dispatcher {#fuse_dispatcher}

FUSE dispatcher library is a helper library for facilitating the translation between FUSE commands
and the fsdev API.  It parses the FUSE "in" headers, translates them to the appropriate
`spdk_fsdev_*` interface, and builds the FUSE "out" headers from the response.  It's also
responsible for mounting and unmounting fsdevs on `FUSE_INIT` and `FUSE_DESTROY`, respectively.

`fuse_dispatcher` is used by both @ref fuse_tgt and @ref vfu_virtio_fs.

## virtio-fs target {#vfu_virtio_fs}

The fsdev library, along with @ref fuse_dispatcher, is used to implement a vfio-user target
implementing a virtio-fs protocol.  This makes it possible to expose fsdevs to QEMU guests.  The
implementation is based on the Nutanix's [libvfio-user
library](https://github.com/nutanix/libvfio-user) and requires QEMU that supports vfio-user
interface.  More information can be found in libvfio-user's
[README](https://github.com/nutanix/libvfio-user/blob/master/README.md).

### Example

The example below shows how to expose AIO fsdev via virito-fs.

```bash
# Start up the target
$ build/bin/spdk_tgt -S /path/to/vfio-user/sockdir

# Create AIO fsdev and attach it to a vfio-user endpoint
$ scripts/rpc.py fsdev_aio_create aio0 /path/to/aiodir
$ scripts/rpc.py vfu_virtio_create_fs_endpoint vfio-fs.0 --fsdev-name aio0 --tag spdk-aio0 \
    --cpumask 0x1 --num-queues 8 --qsize 256 --packed-ring

# Start QEMU and point it to the vfio-user socket
$ qemu ... -device vfio-user-pic,socket=/path/to/vfio-user/sockdir/vfio-fs.0

# Finally, mount the aio fsdev inside the VM
$ modprobe virtiofs
$ mount -t virtiofs spdk-aio0 /mnt
```

## Limitations

Memory domains are currently only supported in the fsdev API and relevant parameters are passed to
the fsdev modules as-is.  This means, that the fsdev layer does not check if a module supports
memory domains and will not do a push/pull if it doesn't.

## Filesystem device modules {#fsdev_modules}

### AIO {#fsdev_aio}

The AIO fsdev uses Linux/POSIX asynchronous IO interface (depending on the operating system) to
execute fsdev operations.  It can be used to expose any directory on the root filesystem over the
fsdev interface.

#### Example

```bash
$ scripts/rpc.py fsdev_aio_create aio0 /path/to/dir
```

## Tools {#fsdev_tools}

There are several tools that are useful for the development, debugging, and testing of fsdev
modules.

### FUSE target {#fuse_tgt}

FUSE target is an application that can be used to mount an fsdev in a local root filesystem using
Linux kernel FUSE driver.  Underneath, it communicates with the kernel via the `/dev/fuse` device
and uses @ref fuse_dispatcher to submit received FUSE requests and send them to a mounted fsdev.
It can be started on multiple cores, in which case it'll spawn a thread on each core and will
process FUSE requests on each one.

The application provides two ways for mounting fsdevs: specifying the fsdev and mountpoint on
the command-line or starting the application in the "daemon" mode and using RPCs.  With RPCs, it's
possible to mount multiple fsdevs at the same time.

#### Example

The first example shows how to use the application to mount an fsdev from command-line:

```bash
# Start the fuse target app
$ build/examples/fuse --fs aio0 --mountpoint /mnt

# Create the aio fsdev
$ scripts/rpc.py fsdev_aio_create aio0 /path/to/dir

# Verify that /path/to/dir is visible in /mnt
$ echo "Hello World!" > /mnt/hello
$ cat /path/to/dir/hello
Hello World!

# Unmounting will stop the app
$ umount /mnt
```

The same can be achieved via RPC:

```bash
# Start the fuse target app in the daemon mode
$ build/examples/fuse -D

# Create the aio fsdev
$ scripts/rpc.py fsdev_aio_create aio0 /path/to/dir

# Mount it
$ scripts/rpc.py fuse_mount aio0 /mnt

# Verify that /path/to/dir is visible in /mnt
$ echo "Hello World!" > /mnt/hello
$ cat /path/to/dir/hello
Hello World!

# It's possible to unmount via umount(1) or fuse_umount RPC
$ scripts/rpc.py fuse_umount aio0
```

### fsdevperf {#fsdevperf}

`fsdevperf` is an application intended for evaluating performance of fsdev modules.  It uses fsdev
API directly and allows users to submit I/O to one or more files located on one or more fsdevs.
Users can control various characteristics of the I/O, such as I/O size, I/O depth, I/O pattern,
number of files, etc.  The tests can be run immediately after starting the application or via the
`perform_tests` RPC (which can be submitted using the helper script located in
`examples/fsdev/fsdevperf/fsdevperf.py`).

#### Example

The following example shows 128 4k random reads to a 10M file called "foo" on aio0 from the CPU
cores.

```bash
$ cat config.json
{
  "subsystems": [
    {
      "subsystem": "fsdev",
      "config": [
        {
          "method": "fsdev_aio_set_options",
          "params": {
            "max_io_depth": 1024,
            "enable_io_uring": false
          }
        },
        {
          "method": "fsdev_aio_create",
          "params": {
            "name": "aio0",
            "root_path": "/path/to/aio0",
            "enable_xattr": false,
            "enable_writeback_cache": true,
            "max_xfer_size": 131072,
            "max_readahead": 131072,
            "skip_rw": false,
            "enable_notifications": false,
            "attr_valid_ms": 0,
            "disable_copy_file_range": false
          }
        }
      ]
    }
  ]
}

$ build/examples/fsdevperf -m 0x3 -w randread -t 8 -q 128 -o 4k -P /aio0/foo -f 10M -c config.json
[2025-03-19 13:38:25.876460] Starting SPDK v25.01-pre git sha1 4c3217387 / DPDK 24.03.0 initialization...
[2025-03-19 13:38:25.876543] [ DPDK EAL parameters: fsdevperf --no-shconf -c 0x3 --huge-unlink --no-telemetry --log-level=lib.eal:6 --log-level=lib.cryptodev:5 --log-level=lib.power:5 --log-level=user1:6 --base-virtaddr=0x200000000000 --match-allocations --file-prefix=spdk_pid846027 ]
[2025-03-19 13:38:25.880640] app.c: 919:spdk_app_start: *NOTICE*: Total cores available: 2
[2025-03-19 13:38:25.887093] reactor.c: 995:reactor_run: *NOTICE*: Reactor started on core 1
[2025-03-19 13:38:25.887102] reactor.c: 995:reactor_run: *NOTICE*: Reactor started on core 0
main (pattern=randread, iosize=4096, iodepth=128, nrfiles=1):
                        filename core    runtime       IOPS      MiB/s
                       /aio0/foo    0       8.00 1309581.87    5115.55
                       /aio0/foo    1       8.00 1308101.24    5109.77
                                                 2617683.11   10225.32
```

It is also possible to send I/O to multiple files using the `--nrfiles` option.  In this case, the
path passed to the `-P` argument should only contain the name of the fsdev.  `fsdevperf` will create
the files prior to running the workload.  For instance, the following example submits random reads
to 4 10M files from each of the two cores.

```bash
$ build/examples/fsdevperf -m 0x3 -w randread -t 5 -q 128 -o 4k -P /aio0 -f 10M -c config.json --nrfiles 4
[2025-03-19 13:40:27.636387] Starting SPDK v25.01-pre git sha1 4c3217387 / DPDK 24.03.0 initialization...
[2025-03-19 13:40:27.636429] [ DPDK EAL parameters: fsdevperf --no-shconf -c 0x3 --huge-unlink --no-telemetry --log-level=lib.eal:6 --log-level=lib.cryptodev:5 --log-level=lib.power:5 --log-level=user1:6 --base-virtaddr=0x200000000000 --match-allocations --file-prefix=spdk_pid846703 ]
[2025-03-19 13:40:27.640375] app.c: 919:spdk_app_start: *NOTICE*: Total cores available: 2
[2025-03-19 13:40:27.647444] reactor.c: 995:reactor_run: *NOTICE*: Reactor started on core 1
[2025-03-19 13:40:27.647480] reactor.c: 995:reactor_run: *NOTICE*: Reactor started on core 0
main (pattern=randread, iosize=4096, iodepth=128, nrfiles=4):
                        filename core    runtime       IOPS      MiB/s
                 /aio0/main.00.0    0       8.00  254256.62     993.19
                 /aio0/main.00.1    0       8.00  254259.08     993.20
                 /aio0/main.00.2    0       8.00  254276.45     993.27
                 /aio0/main.00.3    0       8.00  254281.67     993.29
                 /aio0/main.01.0    1       8.00  271832.90    1061.85
                 /aio0/main.01.1    1       8.00  271839.88    1061.87
                 /aio0/main.01.2    1       8.00  271841.87    1061.88
                 /aio0/main.01.3    1       8.00  271875.90    1062.02
                                                 2104464.35    8220.56
```

As mentioned before, it's also possible to submit IO to more than one fsdev at the same time.  This
can be achieved by specifying the workloads (called jobs) in a config file.  The example below
submits random reads to aio0 and random writes to aio01.  Additionally, aio0 is created after
starting the application and the tests are started through RPC.

```bash
$ cat jobs.conf
[job-read]
path=/aio0
pattern=randread
runtime=8
iodepth=128
iosize=4k
filesize=10M
nrfiles=2

[job-write]
path=/aio1
pattern=randwrite
runtime=8
iodepth=4
iosize=128k
filesize=10M
nrfiles=1

# Start up fsdevperf, but wait for the perform_tests RPC (-z flag)
$ build/examples/fsdevperf -m 0x3 -c config.json -j jobs.conf -z

# Create the second aio fsdev
$ scripts/rpc.py fsdev_aio_create aio1 /path/to/aio1

$ examples/fsdev/fsdevperf/fsdevperf.py perform_tests
[2025-03-19 13:50:21.950191] Starting SPDK v25.01-pre git sha1 4c3217387 / DPDK 24.03.0 initialization...
[2025-03-19 13:50:21.950227] [ DPDK EAL parameters: fsdevperf --no-shconf -c 0x3 --huge-unlink --no-telemetry --log-level=lib.eal:6 --log-level=lib.cryptodev:5 --log-level=lib.power:5 --log-level=user1:6 --base-virtaddr=0x200000000000 --match-allocations --file-prefix=spdk_pid849471 ]
[2025-03-19 13:50:21.954244] app.c: 919:spdk_app_start: *NOTICE*: Total cores available: 2
[2025-03-19 13:50:21.961421] reactor.c: 995:reactor_run: *NOTICE*: Reactor started on core 1
[2025-03-19 13:50:21.961434] reactor.c: 995:reactor_run: *NOTICE*: Reactor started on core 0
job-read (pattern=randread, iosize=4096, iodepth=128, nrfiles=2):
                        filename core    runtime       IOPS      MiB/s
             /aio0/job-read.00.0    0       8.00  491228.42    1918.86
             /aio0/job-read.00.1    0       8.00  491238.15    1918.90
             /aio0/job-read.01.0    1       8.00  478095.80    1867.56
             /aio0/job-read.01.1    1       8.00  478111.33    1867.62
                                                 1938673.70    7572.94
job-write (pattern=randwrite, iosize=131072, iodepth=4, nrfiles=1):
                        filename core    runtime       IOPS      MiB/s
            /aio1/job-write.00.0    0       8.00   15352.61    1919.08
            /aio1/job-write.01.0    1       8.00   14942.86    1867.86
                                                   30295.47    3786.93
```
