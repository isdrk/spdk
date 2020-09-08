#ifndef MLNX_SNAP_UTILS_H
#define MLNX_SNAP_UTILS_H

#include <net/if_arp.h>

#define SNAP_EMU_NAME      "snap_emulator"
#define member_size(type, member) sizeof(((type *)NULL)->member)
#define IFACE_MAX_LEN member_size(struct arpreq, arp_dev)
#define SNAP_EMU_MAX_BCOPY 8192

#define u8 uint8_t
#define BIT(n) (1<<(n))
#define __packed

/* assume little endianess */
#define cpu_to_le64(x) x
#define cpu_to_le32(x) x
#define cpu_to_le16(x) x

#define le64_to_cpu(x) x
#define le32_to_cpu(x) x
#define le16_to_cpu(x) x

#define NVME_ADM_CMD_VS_JSON_RPC_2_0_REQ 0xc1
#define NVME_ADM_CMD_VS_JSON_RPC_2_0_RSP 0xc2

#define MLNX_SNAP_FATAL(_fmt, ...) \
    do { \
        SPDK_ERRLOG(_fmt, ## __VA_ARGS__); \
        abort(); \
    } while(0);

#define MLNX_SNAP_FATALV_COND(_expr, _fmt, ...) \
    do { \
        if (!(_expr)) { \
            MLNX_SNAP_FATAL("assertion failure: %s " _fmt, #_expr, ## __VA_ARGS__); \
        } \
    } while(0);

int nvmf_mlnx_snap_dev_to_iface(const char *dev, char *iface);

#endif //MLNX_SNAP_UTILS_H
