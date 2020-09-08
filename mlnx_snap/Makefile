ifneq ($(V),1)
Q ?= @
endif

CC = gcc

DIR := ${CURDIR}/

#TODO: assume that SPDK root directory is ../
SPDK_ROOT_DIR=$(abspath ../)

SO_SRCS = mlnx_snap.c devx_verbs.c mlnx_snap_utils.c devx_compat.c
SO_OBJS := $(SO_SRCS:.c=.o)
SO_NAME = libspdk_mlnx_snap.so

#log sock util nvme thread json jsonrpc rpc trace bdev
#SPDK_LIBS = -lspdk_nvmf -lspdk_log -lspdk_json
SPDK_LIBS = -lspdk_log -lspdk_json
SPDK_LIBS += -lspdk_env_dpdk
SPDK_LIBS += -lrte_mempool
SPDK_LIBS += -lrte_eal
SPDK_LIBS += -lrte_kvargs -lrte_telemetry -lrte_ring
SNAP_LIBS = -lsnap
SYS_LIBS = -libverbs -lmlx5

ifeq ($(SPDK_LIB_DIR),)
$(error SPDK_LIB_DIR is not specified)
endif
ifeq ($(DPDK_LIB_DIR),)
$(error DPDK_LIB_DIR is not specified)
endif
ifeq ($(SPDK_INC_DIR),)
$(error SPDK_INC_DIR is not specified)
endif

SPDK_LIB_DIR_ABS=$(abspath $(SPDK_LIB_DIR))
DPDK_LIB_DIR_ABS=$(abspath $(DPDK_LIB_DIR))
SPDK_INC_DIR_ABS=$(abspath $(SPDK_INC_DIR))
#SNAP_LIB_DIR_ABS ?= /usr/local/snap/lib
SNAP_LIB_DIR_ABS ?= /lib/aarch64-linux-gnu/snap_old

#CFLAGS = -g -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-declarations -fno-strict-aliasing -D_GNU_SOURCE -fPIC -fstack-protector -fno-common
CFLAGS = -g -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-declarations -fno-strict-aliasing -D_GNU_SOURCE -fPIC -fstack-protector
CFLAGS += -I$(SPDK_INC_DIR_ABS)
#TODO: this is a dirty hack. We need it to include nvmf_internal.h to use only 1
#function _nvmf_subsystem_get_ns. This function returns a pointer to spdk_nvmf_ns
#structure and we only need it to get block size.
#Probably we can create a function somewhere in include/spdk_internal to get
#block size by nsid
CFLAGS += -I$(SPDK_ROOT_DIR)/lib/nvmf

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG
endif

LDFLAGS = -Wl,-z,noexecstack
LDFLAGS += -L$(SPDK_LIB_DIR_ABS)
LDFLAGS += -L$(DPDK_LIB_DIR_ABS)
LDFLAGS += -L$(SNAP_LIB_DIR_ABS)
LDFLAGS += $(SNAP_LIBS)
LDFLAGS += $(SPDK_LIBS)
LDFLAGS += $(SYS_LIBS)
LDFLAGS += -Wl,-rpath,$(SPDK_LIB_DIR_ABS)
LDFLAGS += -Wl,-rpath,$(DPDK_LIB_DIR_ABS)
LDFLAGS += -Wl,-rpath,$(SNAP_LIB_DIR_ABS)


#LD_STATIC = -lspdk_nvme -lspdk_env_dpdk -lspdk_util -lspdk_log -lspdk_sock
#LD_STATIC += -lrte_eal -lrte_mempool -lrte_kvargs -lrte_ring -lrte_bus_pci -lrte_pci
#LD_DYNAMIC = -lpthread -libverbs -lrdmacm -luuid -lnuma -lcudart
#LDFLAGS += -Wl,-Bstatic $(LD_STATIC)
#LDFLAGS += -Wl,-Bdynamic $(LD_DYNAMIC)

%.o: %.c
	$(Q)echo "Compiling $<"
	$(Q)$(CC) -c $(CFLAGS)  $< -o $@

$(SO_NAME): $(SO_OBJS)
	$(Q)echo "Building $(SO_NAME)"
	$(Q)$(CC) $(CFLAGS) -shared -Wl,-soname,$(SO_NAME) $(SO_OBJS) $(LDFLAGS) -o $(SO_NAME)

all: $(SO_NAME)

clean:
	$(Q)echo "Clean lib"
	$(Q)rm -f *.so
	$(Q)rm -f *.o
