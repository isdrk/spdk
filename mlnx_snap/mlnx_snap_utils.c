//
// Created by alexeymar on 12-Oct-20.
//

#include "mlnx_snap_utils.h"

#include <glob.h>

#include <spdk/log.h>

#define IB_PREFIX "/sys/class/infiniband/"
#define NET_PREFIX "/sys/class/net/"
#define SUFFIX "/device/resource"
#define SF_SUFFIX "/ports/1/gid_attrs/ndevs/0"
#define MLX_SUFFIX "/device/infiniband/*"

static int
nvmf_mlnx_snap_diff_files(const char *fpath1, const char *fpath2)
{
	FILE *f1, *f2;
	int c1, c2;
	int ret = 0;

	f1 = fopen(fpath1, "r");
	if (!f1) {
		SPDK_ERRLOG("Failed to open file %s: %d\n", fpath1, errno);
		return -errno;
	}

	f2 = fopen(fpath2, "r");
	if (!f2) {
		SPDK_ERRLOG("Failed to open file %s: %d\n", fpath2, errno);
		fclose(f1);
		return -errno;
	}

	do {
		c1 = getc(f1);
		c2 = getc(f2);
	} while ((c1 == c2) && c1 != EOF && c2 != EOF);

	if (c1 != EOF || c2 != EOF) {
		ret = 1;
	}

	fclose(f2);
	fclose(f1);
	return ret;
}

/* Checks whether a network interface is a representor,
 * Based on it's dev_port attribute.
 * The check follows the nvmx kernel convention given in
 * commit 505cb6ad on nvmx-kernel repository
 *
 * returns: On success - 1 if representor, 0 if not.
 *          On failure - ret < 0
 */
static int nvmf_mlnx_snap_is_representor(const char *iface)
{
	FILE *fp;
	char dev_port_path[PATH_MAX];
	char line[256];
	int ret = 0;

	snprintf(dev_port_path, sizeof(dev_port_path),
		 NET_PREFIX"%s/dev_port", iface);

	fp = fopen(dev_port_path, "r");
	if (!fp) {
		SPDK_ERRLOG("Failed to open file %s: %d\n", dev_port_path, errno);
		return -errno;
	}

	//dev_port should be 0 for device, and != for representors
	if (NULL == fgets(line, sizeof(line) - 1, fp)) {
		SPDK_ERRLOG("Failed to read file %s: %d\n", dev_port_path, errno);
		ret = -errno;
		fclose(fp);
		return ret;
	}
	if (atoi(line) != 0) {
		ret = 1;
	}

	//dev_port should be single-lined file
	if (fgets(line, sizeof(line) - 1, fp)) {
		ret = -EINVAL;
	}

	fclose(fp);
	return ret;
}

int nvmf_mlnx_snap_dev_to_iface(const char *dev, char *iface)
{
	char ibdev_res_path[PATH_MAX], netdev_res_path[PATH_MAX], **p;
	char ibdev_sf_res_path[PATH_MAX];
	char line[256];
	const char *_iface;
	glob_t glob_entry = {0,};
	int i = 0;
	FILE *fp;
	int ret = -ENODEV;

	snprintf(ibdev_res_path, sizeof(ibdev_res_path), IB_PREFIX"%s"SUFFIX, dev);
	snprintf(ibdev_sf_res_path, sizeof(ibdev_sf_res_path), IB_PREFIX"%s"SF_SUFFIX, dev);
	glob(NET_PREFIX"*", 0, 0, &glob_entry);
	p = glob_entry.gl_pathv;

	/* first try to check SF path */
	fp = fopen(ibdev_sf_res_path, "r");
	if (!fp) {
		SPDK_WARNLOG("Failed to open file %s: %d. fallback to non SF check\n", ibdev_sf_res_path, errno);
	} else {
		if (fgets(line, sizeof(line), fp) == NULL) {
			SPDK_ERRLOG("Failed to read file %s: %d\n", ibdev_sf_res_path, errno);
			ret = -errno;
		} else {
			while (line[i++] != '\n');
			line[i - 1] = '\0';
			snprintf(netdev_res_path, sizeof(netdev_res_path), "%s%s", NET_PREFIX, line);
			if (access(netdev_res_path, F_OK) != -1) {
				memcpy(iface, line, IFACE_MAX_LEN);
				ret = 0;
			} else {
				ret = -ENODEV;
			}
		}
		fclose(fp);
		return ret;
	}

	if (glob_entry.gl_pathc >= 1)
		for (i = 0; i < glob_entry.gl_pathc; i++, p++) {
			snprintf(netdev_res_path, sizeof(netdev_res_path), "%s"SUFFIX, *p);
			_iface = *p + strlen(NET_PREFIX);
			if (access(netdev_res_path, F_OK) != -1 &&
			    nvmf_mlnx_snap_diff_files(ibdev_res_path, netdev_res_path) == 0) {
				if (nvmf_mlnx_snap_is_representor(_iface)) {
					continue;
				}
				strncpy(iface, _iface, IFACE_MAX_LEN - 1);
				ret = 0;
				break;
			}
		}
	globfree(&glob_entry);

	return ret;
}
