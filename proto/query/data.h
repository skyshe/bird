#ifndef _BIRD_QUERY_DATA_H_
#define _BIRD_QUERY_DATA_H_

#include "lib/ip.h"

#include <pthread.h>
#include <zlib.h>

/*
 * Data structure:
 *
 * There are blocks of 512 bytes, either links or data.
 * Each block resides at (base + 512*K) where K is the block's ID.
 * Block K = 0 is reserved for locks and other stuff.
 *
 * The Link block represents a part of IP prefix tree traversed (roughly) this way:
 *    1. Split the IP prefix to chunks of 6 bits; last chunk may be shorter.
 *	 If the prefix length is divisible by 6, there is a zero-length last chunk.
 *    2. Select the root Link block at K=1.
 *    3. While the first chunk's length is 6:
 *    3.1. K = link[chunk]
 *    3.2. Drop the first chunk.
 *    4. Now the only chunk left must be shorter than 6.
 *    5. The data chunk ID for this prefix is D = data<chunk length>[chunk]
 * The parent field in Link block is used for consistency checks and also for better memory defragmentation.
 *
 * The Data block is documented below.
 */

#define QUERY_LINK_TO_DATA_BIT	0x80000000U

#define QUERY_NODE_TYPE_HEADER	1
#define QUERY_NODE_TYPE_LINK	2
#define QUERY_NODE_TYPE_DATA	3

static inline u32 query_cpx(ip_addr prefix, uint sofar, uint len) {
  return ipa_getbitrange(prefix, sofar, len) | (len << 24);
}

struct query_header {
  u8 type;		//  QUERY_NODE_TYPE_HEADER
  u8 unused[3];
  pthread_rwlock_t lock;
  pthread_rwlockattr_t lockattr;
};

struct query_link {
  u8 type;		//  QUERY_NODE_TYPE_LINK
  u8 count_data;	//  number of occupied data positions
  u8 count_link;	//  number of occupied link positions
  u8 unused;
  u32 data0[1];		//   4
  u32 data1[2];		//   8
  u32 data2[4];		//  16
  u32 data3[8];		//  32
  u32 data4[16];	//  64
  u32 data5[32];	// 128
  u32 link[64];		// 256
			// 512 bytes total.
};

static inline u32 query_link_hash(u32 cpx) { return u32_hash(cpx) % 63; }

#define QUERY_DATA_BUFLEN   504

struct query_data {
  u8 type;		//  QUERY_NODE_TYPE_DATA
  u8 unused;
  u16 length;		// Length of the data stored.
  u32 next;		// Zero or pointer to the continuation.
  char data[QUERY_DATA_BUFLEN];
};

typedef union query_node {
  u8 type;
  struct query_header h;
  struct query_link l;
  struct query_data d;
} query_node;

/*
 * 2^31 * sizeof(query_node) = 2^31 * 512 = 2^40 bytes of memory = 1 TB max limit on shared memory.
 */

#endif
