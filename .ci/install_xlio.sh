#!/bin/bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

set -e

XLIO_SHA=${1:-671c455f}

install_xlio(){
	git clone https://github.com/Mellanox/libxlio.git /tmp/libxlio
	cd /tmp/libxlio || exit 1
	git fetch --tags
	git checkout "$XLIO_SHA"

	./autogen.sh
	./configure --prefix=/tmp/libxlio/install --enable-utls --with-dpcp=/tmp/libdpcp/install
	make "-j$(nproc)"
	make install
}

install_dpcp(){
	# Install libdpcp 1.1.52
	git clone --depth 1 https://github.com/Mellanox/libdpcp.git /tmp/libdpcp
	cd /tmp/libdpcp || exit 1
	git checkout 5960d78ba2c88a9d991a57edfbddebea4bd1dd13

	./autogen.sh
	./configure --prefix=/tmp/libdpcp/install
	make "-j$(nproc)"
	make install
}

install_dpcp
install_xlio
