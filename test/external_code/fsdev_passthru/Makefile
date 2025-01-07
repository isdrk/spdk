#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

src=vfsdev_passthru_rpc.c vfsdev_passthru.c
shared:
	$(CC) $(COMMON_CFLAGS) -c -fPIC ./vfsdev_passthru_rpc.c -o ./vfsdev_passthru_rpc.o
	$(CC) $(COMMON_CFLAGS) -c -fPIC ./vfsdev_passthru.c -o ./vfsdev_passthru.o
	$(CC) $(COMMON_CFLAGS) -shared ./vfsdev_passthru_rpc.o ./vfsdev_passthru.o -o ./libfsdev_passthru_external.so

static:
	$(CC) $(COMMON_CFLAGS) -c ./vfsdev_passthru_rpc.c -o ./vfsdev_passthru_rpc.o
	$(CC) $(COMMON_CFLAGS) -c ./vfsdev_passthru.c -o ./vfsdev_passthru.o
	$(AR) rcs ./libfsdev_passthru_external.a ./vfsdev_passthru_rpc.o ./vfsdev_passthru.o
