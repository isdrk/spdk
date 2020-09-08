#ifndef _NVME_REGS_H
#define _NVME_REGS_H

/* length of area that contains command registers
 * excluding CQ/SQ and doorbels
 */
#define NVME_EMU_REGS_SIZE  0x50

/* NVME registers */
#define SNAP_NVME_REG_CAP    0x00     /* capabilities */
#define SNAP_NVME_REG_VS     0x08     /* version */
#define SNAP_NVME_REG_INTMS  0x0C     /* interrupt mask set */
#define SNAP_NVME_REG_INTMC  0x10     /* interrupt mask clear */
#define SNAP_NVME_REG_CC     0x14     /* Controller config */
#define SNAP_NVME_REG_CSTS   0x1C     /* Controller status */
#define SNAP_NVME_REG_NSSR   0x20     /* NVM subsystem reset */
#define SNAP_NVME_REG_AQA    0x24     /* Admin Queue Attrs */
#define SNAP_NVME_REG_ASQ    0x28     /* Admin Submission Queue Base Addr */
#define SNAP_NVME_REG_ACQ    0x30     /* Admin Completion Queue Base Addr */
/* Optional registers */
#define SNAP_NVME_REG_CMBLOC 0x38     /* Controller memory buffer location */
#define SNAP_NVME_REG_CMBSZ  0x3C     /* Controller memory buffer size */
#define SNAP_NVME_REG_BPINFO 0x40     /* Boot partition info */
#define SNAP_NVME_REG_BPRSEL 0x44     /* Boot partition read select */
#define SNAP_NVME_REG_BPMBL  0x48     /* Boot prtition memory buffer */
#define SNAP_NVME_REG_LAST   (-1U)

#define NVME_DB_BASE    0x1000   /* offset of SQ/CQ doorbells */

#define NVME_BIT(n)   (1u<<(n))

/* register indexes */
#define SNAP_NVME_REG_CAP_IDX    0
#define SNAP_NVME_REG_VS_IDX     1
#define SNAP_NVME_REG_INTMS_IDX  2
#define SNAP_NVME_REG_INTMC_IDX  3
#define SNAP_NVME_REG_CC_IDX     4
#define SNAP_NVME_REG_CSTS_IDX   5
#define SNAP_NVME_REG_NSSR_IDX   6
#define SNAP_NVME_REG_AQA_IDX    7
#define SNAP_NVME_REG_ASQ_IDX    8
#define SNAP_NVME_REG_ACQ_IDX    9
/* Optional registers */
#define SNAP_NVME_REG_CMBLOC_IDX 10
#define SNAP_NVME_REG_CMBSZ_IDX  11
#define SNAP_NVME_REG_BPINFO_IDX 12
#define SNAP_NVME_REG_BPRSEL_IDX 13
#define SNAP_NVME_REG_BPMBL_IDX  14

#define SNAP_NVME_REG_MAX_DUMP_FUNC_LEN   256

enum {
	SNAP_NVME_REG_RO   = NVME_BIT(0),    /* read only */
	SNAP_NVME_REG_RW   = NVME_BIT(1),    /* read/write */
	SNAP_NVME_REG_RW1S = NVME_BIT(2),    /* read/write 1 to set */
	SNAP_NVME_REG_RW1C = NVME_BIT(3)     /* read/write 1 to clear */
};

typedef void (*nvme_reg_dump_func_t)(uint64_t reg, char *dump);

struct nvmf_mlnx_snap_nvme_register {
	unsigned              reg_base;
	unsigned              reg_size;
	uint8_t               reg_type;
	const char           *name;
	const char           *desc;
	nvme_reg_dump_func_t  reg_dump_func;
};


struct nvmf_mlnx_snap_nvme_bar {
	/** controller capabilities */
	union spdk_nvme_cap_register	cap;

	/** version of NVMe specification */
	union spdk_nvme_vs_register	vs;
	uint32_t			intms; /* interrupt mask set */
	uint32_t			intmc; /* interrupt mask clear */

	/** controller configuration */
	union spdk_nvme_cc_register	cc;

	uint32_t			reserved1;
	union spdk_nvme_csts_register	csts; /* controller status */
	uint32_t			nssr; /* NVM subsystem reset */

	/** admin queue attributes */
	union spdk_nvme_aqa_register	aqa;

	uint64_t			asq; /* admin submission queue base addr */
	uint64_t			acq; /* admin completion queue base addr */
	/** controller memory buffer location */
	union spdk_nvme_cmbloc_register	cmbloc;
	/** controller memory buffer size */
	union spdk_nvme_cmbsz_register	cmbsz;

	/** boot partition information */
	union spdk_nvme_bpinfo_register	bpinfo;
};

struct nvmf_mlnx_snap_nvme_bar_instance {
	struct nvmf_mlnx_snap_nvme_bar    curr;
	struct nvmf_mlnx_snap_nvme_bar    prev;
	void          *ucontext;
};

typedef int (*nvme_bar_read_func_t)(void *ucontext, void *buf, uint32_t addr, unsigned len);
typedef int (*nvme_bar_write_func_t)(void *ucontext, void *buf, uint32_t addr, unsigned len);

/* called when register is modified */
typedef void (*nvme_reg_mod_cb_func_t)(void *bar, struct nvmf_mlnx_snap_nvme_register *reg,
				       uint64_t val,
				       uint64_t prev_val);

/* initialize bar and read cap & vs regs */
int nvme_bar_init(nvme_bar_read_func_t bar_reader, struct nvmf_mlnx_snap_nvme_bar_instance *bar,
		  void *ucontext);
int nvme_bar_init_modify(nvme_bar_write_func_t bar_writer,
			 struct nvmf_mlnx_snap_nvme_bar_instance *bar, void *ucontext);

/* update whole bar
 * Calls callback for each modified register
 */
int nvme_bar_update(struct nvmf_mlnx_snap_nvme_bar_instance *bar, nvme_bar_read_func_t bar_reader,
		    nvme_reg_mod_cb_func_t cb);

/* dump a whole bar */
void nvme_bar_dump(void *bar, unsigned len);
/* dump register with given index */
void nvme_reg_dump(struct nvmf_mlnx_snap_nvme_register *reg, void *bar, bool user_mode);

uint64_t nvme_reg_get(struct nvmf_mlnx_snap_nvme_register *reg, void *bar);
void nvme_reg_set(struct nvmf_mlnx_snap_nvme_register *reg, void *bar, uint64_t val);

#endif

