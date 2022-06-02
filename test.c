#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <dlfcn.h>
#include <asm/byteorder.h>
#include <infiniband/mad.h>


// Convert BYTES - DWORDS with MEMCPY BE
#define BYTES_TO_DWORD_BE(dw_dest, byte_src) do {   u_int32_t tmp; \
                                                    memcpy(&tmp, byte_src, 4); \
                                                    *(dw_dest) = __be32_to_cpu(tmp); \
} while (0)

#define DWORD_TO_BYTES_BE(bytes_dest, dw_src) do { u_int32_t tmp; \
                                                   tmp = __cpu_to_be32(*(dw_src)); \
                                                   memcpy(bytes_dest, &tmp, 4); \
} while (0)

#define IBERROR(args) do {               printf("-E- ibvsmad : "); \
                                         printf args; \
                                         printf("\n"); \
                                         errno = EINVAL; \
} while (0)

#define CHECK_NULL(pointer) if (pointer == NULL) {return -1;}

#define IB_DATA_INDEX     8
#define MAX_IB_SMP_DATA_SIZE    (IB_SMP_DATA_SIZE - IB_DATA_INDEX)
#define MAX_IB_SMP_DATA_DW_NUM  MAX_IB_SMP_DATA_SIZE / 4

#define CONFIG_ACCESS_MODE_2_DATA_OFFSET 4
#define CONFIG_ACCESS_MODE_2_BITMASK_OFFSET 8

#define IB_VS_ATTR_CR_ACCESS            0x50

// ConfigSpaceAccess Mode 0 supports address of up to 24 bits.
#define MODE_0_MAX_ADDRESS_RANGE 0x7FFFFF
#define MODE_2_MAX_RECORDS_NUM   18
#define MODE_2_MAX_DATA_SIZE     (MODE_2_MAX_RECORDS_NUM * 4)

#define  MAX_VS_DATA_SIZE (IB_VENDOR_RANGE1_DATA_SIZE -  IB_DATA_INDEX)
#define  MAX_IB_VS_DATA_DW_NUM  MAX_VS_DATA_SIZE / 4

#define BAD_RET_VAL ~0llu

#define ONES32(size)                    ((size) ? (0xffffffff >> (32 - (size))) : 0)

#define EXTRACT_C(source, offset, size)   ((((unsigned)(source)) >> (offset)) & ONES32(size))
#define EXTRACT(src, start, len)          (((len) == 32) ? (src) : EXTRACT_C(src, start, len))

static unsigned int should_use_mode_2(u_int32_t memory_address, u_int8_t num_of_dwords)
{
	return memory_address + (num_of_dwords * 4) >
		MODE_0_MAX_ADDRESS_RANGE ? 1 : 0;
}

// Attribute modifier for mode 0:
// Bits 24-31: Address MSB
// Bits 22-23: Mode = 0
// Bits 16-21: Number of dwords
// Bits 0-15: Address LSB
static u_int32_t create_attribute_mode_0(u_int32_t memory_address, u_int8_t num_of_dwords)
{
    return ( (EXTRACT(memory_address, 0, 16) << 00) & 0x0000ffff ) |
           ( (num_of_dwords << 16) & 0x00ff0000 ) |
           ( (EXTRACT(memory_address, 16, 8) << 24) & 0xff000000 );
}

// Attribute modifier for mode 2:
// Bits 22-23: Mode = 2
// Bits 16-21: Number of records (= number of dwords)
static u_int32_t create_attribute_mode_2(u_int8_t num_of_dwords)
{
    return  ( ( ( 2 << 22) & 0x800000 ) |
            ( (num_of_dwords << 16) & 0x00ff0000 ));
}

static void set_mad_data_for_mode_2(u_int32_t memory_address, u_int8_t num_of_dwords,
					u_int8_t* mad_data, u_int32_t* attribute_mod,
					u_int32_t* mask, unsigned int* data_offset)
{
	int i = 0;
	*attribute_mod = create_attribute_mode_2(num_of_dwords);

	// First dword of each record of ConfigSpaceAccess mode 2
	// contains the current address.
	for (i = 0; i < num_of_dwords; i++) {
		u_int32_t record_offset = memory_address + i;
		DWORD_TO_BYTES_BE(mad_data + IB_DATA_INDEX + (i * 4), &record_offset);
	}

	// Second dword contains the data.
	*data_offset = CONFIG_ACCESS_MODE_2_DATA_OFFSET;

	// Third dword contains the bitmask.
	*mask = 0xFFFFFFFF;
}

static uint64_t ibvsmad_craccess_rw_smp(u_int32_t memory_address, int method, u_int8_t num_of_dwords, u_int32_t *data)
{
	u_int8_t mad_data[IB_SMP_DATA_SIZE] = {0};
	int i;
	u_int32_t attribute_mod = 0;
	u_int64_t mkey = 0;
	u_int32_t mask = 0;
	unsigned int data_offset = 0;
	unsigned int use_mode_2 = should_use_mode_2(memory_address, num_of_dwords);
	int rv;

	if (num_of_dwords > MAX_IB_SMP_DATA_DW_NUM) {
		IBERROR(("size is too big, maximum number of dwords is %d", MAX_IB_SMP_DATA_DW_NUM));
		return BAD_RET_VAL;
	}

	if (use_mode_2) {
		set_mad_data_for_mode_2(memory_address, num_of_dwords,
					mad_data, &attribute_mod,
					&mask, &data_offset);
	} else {
		attribute_mod = create_attribute_mode_0(memory_address, num_of_dwords);
	}
	if (method == IB_MAD_METHOD_GET) {
		for (i = 0; i < num_of_dwords; i++) {
			BYTES_TO_DWORD_BE(data + i, mad_data + IB_DATA_INDEX + data_offset + (i * 4));
			rv = IB_DATA_INDEX + data_offset + (i * 4);
			printf("line 134 %d\n", rv);
		}			
	} else {
		for (i = 0; i < num_of_dwords; i++) {
			DWORD_TO_BYTES_BE(mad_data + IB_DATA_INDEX + data_offset + (i * 4), data + i);
			rv = IB_DATA_INDEX + data_offset + (i * 4);
			printf("line 140 %d\n", rv);
			DWORD_TO_BYTES_BE(mad_data + IB_DATA_INDEX + CONFIG_ACCESS_MODE_2_BITMASK_OFFSET + (i * 4), &mask);
			rv = IB_DATA_INDEX + CONFIG_ACCESS_MODE_2_BITMASK_OFFSET + (i * 4);
			printf("line 143 %d\n", rv);
		}
	}

	return 0;
}

static uint64_t ibvsmad_craccess_rw_vs(u_int32_t memory_address,int method, u_int8_t num_of_dwords, u_int32_t *data)
{
	u_int8_t vsmad_data[IB_VENDOR_RANGE1_DATA_SIZE] = {0};
	ib_vendor_call_t call;
	int i;
	u_int32_t attribute_mod = 0;
	u_int32_t mask = 0;
	u_int64_t vskey = 0;
	unsigned int data_offset = 0;
	int use_mode_2 = should_use_mode_2(memory_address, num_of_dwords);
	int rv;

	if (data == NULL)
		return BAD_RET_VAL;

	if (num_of_dwords > MAX_IB_VS_DATA_DW_NUM) {
		IBERROR(("size (%d) is too big, maximum num of dwords is %d", num_of_dwords,
		MAX_IB_VS_DATA_DW_NUM));
		return BAD_RET_VAL;
	}

	if (use_mode_2) {
		set_mad_data_for_mode_2(memory_address, num_of_dwords,
					vsmad_data, &attribute_mod,
					&mask, &data_offset);
	} else {
	attribute_mod = create_attribute_mode_0(memory_address, num_of_dwords);
	}

	for (i = 0; i < num_of_dwords; i++) {
		if (method == IB_MAD_METHOD_SET) {
			DWORD_TO_BYTES_BE(vsmad_data + IB_DATA_INDEX + data_offset + (i * 4), data + i);
			rv = IB_DATA_INDEX + data_offset + (i * 4);
			printf("line 183 %d\n", rv);
			DWORD_TO_BYTES_BE(vsmad_data + IB_DATA_INDEX + CONFIG_ACCESS_MODE_2_BITMASK_OFFSET + (i * 4), &mask);
			rv = IB_DATA_INDEX + CONFIG_ACCESS_MODE_2_BITMASK_OFFSET + (i * 4);
			printf("line 186 %d\n", rv);
		}
	}

	for (i = 0; i < num_of_dwords; i++) {
		BYTES_TO_DWORD_BE(data + i, vsmad_data + IB_DATA_INDEX + data_offset + (i * 4));
		rv = IB_DATA_INDEX + data_offset + (i * 4);
		printf("line 193 %d\n", rv);
	}	
	return 0;
}

int main()
{
	u_int32_t memory_address = 0;
	int method = IB_MAD_METHOD_SET;
	u_int8_t num_of_dwords = 14;
	u_int32_t data = 0;

	ibvsmad_craccess_rw_smp(memory_address, method,num_of_dwords, &data);
	ibvsmad_craccess_rw_vs(memory_address, method, num_of_dwords, &data);

	return 0;
}