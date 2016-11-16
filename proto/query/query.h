#ifndef _BIRD_QUERY_H_
#define _BIRD_QUERY_H_

#include "nest/route.h"
#include "nest/bfd.h"
#include "lib/event.h"
#include "lib/hash.h"
#include "lib/ip.h"
#include "lib/socket.h"

#include <zlib.h>

struct query_config {
  struct proto_config c;
  char *shm;
  size_t size;
};

struct query_proto {
  struct proto p;
  void *mem;
  int fd;
  HASH(struct query_net_hash_node) qnh;
  list qnhq;
  slab *qnh_slab;
  event *qnh_event;
  struct query_free_block *qf;
  u32 highest_node;
  u32 max_node;
  slab *qf_slab;
  z_stream zs;
};

struct query_free_block {
  struct query_free_block *next;
  u32 begin;
  u32 end;
};

struct query_net_hash_node {
  node n;
  struct query_net_hash_node *next;
  bird_clock_t born;
  int pxlen;
  ip_addr prefix;
};

#define QNH_KEY(n) n->pxlen, n->prefix
#define QNH_NEXT(n) n->next
#define QNH_EQ(l1, p1, l2, p2) (l1 == l2) && ipa_equal(p1, p2)
#define QNH_FN(l, p) ipa_hash(p) // ^ u32_hash(l)

#define QNH_REHASH qnh_rehash
#define QNH_PARAMS /2, *2, 1, 1, 4, 20
#define QNH_INIT_ORDER	4

#endif
