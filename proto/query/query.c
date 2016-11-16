#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"

#include "filter/filter.h"

#include "proto/query/query.h"
#include "proto/query/data.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void query_free_node(struct query_proto *p, u32 n) {
  debug("%s: Freeing node %u", p->p.name, n);
  if (n <= 1)
    bug("%s: Tried to free a %s from shm", p->p.name, (n ? "root node" : "header node"));

  if (n > p->highest_node)
    bug("%s: Tried to free node %u from shm but max node is %u", p->p.name, n, p->highest_node);

  query_node *qn = p->mem;
  qn[n].type = 0;

  if (n == p->highest_node) {
    p->highest_node--;
    return;
  }

  struct query_free_block **qff = &(p->qf);
  while ((*qff) && (*qff)->end < n)
    qff = &((*qff)->next);

  /* Now *qff is either NULL (and then qff is the last ->next pointer)
   * or the block ending right at the being-freed node
   * or the block containing the already-freed node (BUG!)
   * or the block beginning right after that
   * or the first block after that (and then qff is the [first block before]'s ->next pointer)
   */

  if (!(*qff)) {
    /* This free node is the highest numbered. Creating new qfblock. */
    *qff = sl_alloc(p->qf_slab);
    (*qff)->begin = n;
    (*qff)->end = n+1;
    (*qff)->next = NULL;
    return;
  }

  if ((*qff)->end == p->highest_node + 1) {
    /* This qfblock is at the end of the allocated data, shrinking it all. */
    p->highest_node = (*qff)->begin - 1;
    sl_free(p->qf_slab, (*qff));
    *qff = NULL;
    return query_free_node(p, n); /* Retry after shrinkage. */
  }

  if ((*qff)->end == n) {
    /* This qfblock ends right before the free node. Stretching it. */
    (*qff)->end++;
    if ((*qff)->next && ((*qff)->next->begin == (*qff)->end)) {
      /* Try to merge qfblocks if possible. */
      struct query_free_block *qfx = (*qff);
      (*qff)->next->begin = (*qff)->begin;
      (*qff) = (*qff)->next;
      sl_free(p->qf_slab, qfx);
    }
    return;
  }

  if (((*qff)->begin <= n) && ((*qff)->end > n))
    bug("%s: Tried to free node %u but the range %u..%u already marked as free", p->p.name, n, (*qff)->begin, (*qff)->end);

  if ((*qff)->begin == n+1) {
    /* This qfblock begins right after the free node. Stretching it. */
    (*qff)->begin--;
    return;
    /* No need for block merging, it is done in the previous if. */
  }

  /* No qfblock nearby. */

  struct query_free_block *qfn = sl_alloc(p->qf_slab);
  qfn->next = *qff;
  *qff = qfn;
  qfn->begin = n;
  qfn->end = n+1;
  return;
}

static void query_free_chain(struct query_proto *p, u32 pos) {
  query_node *qn = p->mem;
  while (pos) {
    u32 next = qn[pos].d.next;
    qn[pos].d.next = 0;
    query_free_node(p, pos);
    pos = next;
  }
}

static u32 query_zero_node(struct query_proto *p, u32 pos) {
  query_node *qn = p->mem;
  memset(&qn[pos], 0, sizeof(query_node));
  return pos;
}

static u32 query_alloc(struct query_proto *p) {
  u32 out = 0;
  if (p->qf) {
    out = p->qf->begin++;
    if (p->qf->begin == p->qf->end) {
      struct query_free_block *qff = p->qf;
      p->qf = qff->next;
      sl_free(p->qf_slab, qff);
    }
    debug("%s: Allocated node %u", p->p.name, out);
    return query_zero_node(p, out);
  }

  if (p->highest_node == p->max_node) {
    log(L_ERR "%p: Out of shared memory", p->p.name);
    return 0;
  }

  out = ++p->highest_node;

  debug("%s: Allocated node %u", p->p.name, out);
  return query_zero_node(p, out);
}

HASH_DEFINE_REHASH_FN(QNH, struct query_net_hash_node)


static struct query_data *
query_get(struct query_proto *p, ip_addr prefix, uint pxlen) {
  query_node *qn = p->mem;

#define QUERY_TREE_GET
#include "proto/query/tree.c"
}

static struct query_data *
query_need_more_data(struct query_proto *p, struct query_data *d) {
  query_node *qn = p->mem;
  debug("%s: query_need_more_data: %s", p->p.name, d->next ? "have" : "alloc");
  if (!d->next)
    d->next = query_alloc(p);
  
  if (!d->next)
    return NULL;
  else
    qn[d->next].type = QUERY_NODE_TYPE_DATA;

  return &(qn[d->next].d);
}

static void
query_delete(struct query_proto *p, ip_addr prefix, uint pxlen) {
  query_node *qn = p->mem;

#define QUERY_TREE_DELETE
#include "proto/query/tree.c"
}

static void query_fake_cli_event_hook(void *p UNUSED) {};
static event query_fake_cli_event = { .hook = query_fake_cli_event_hook };

static void
query_update_db(void *data)
{
  struct query_proto *p = data;
  query_node *qn = p->mem;

  pthread_rwlock_wrlock(&qn->h.lock);

  int event_limit = 16;

  pool *update_pool = rp_new(p->p.pool, "query update pool");

  while (!EMPTY_LIST(p->qnhq)) {
    struct query_net_hash_node *qnhn = HEAD(p->qnhq);
    net *n = net_find(p->p.table, qnhn->prefix, qnhn->pxlen);
    if (n && n->routes) {
      struct rt_show_data rsd = {
	.prefix = qnhn->prefix,
	.pxlen = qnhn->pxlen,
	.table = p->p.table,
	.filter = FILTER_ACCEPT,
	.verbose = 1
      };

      struct cli query_cli = { .pool = update_pool, .event = &query_fake_cli_event };
      rt_show_net(&query_cli, n, &rsd);

      debug("%s: query_get(%I/%u)", p->p.name, qnhn->prefix, qnhn->pxlen);

      struct query_data *qd = query_get(p, qnhn->prefix, qnhn->pxlen), *qdd = qd;
      if (!qd) {
	rem_node(&(qnhn->n));
	add_tail(&(p->qnhq), &(qnhn->n));
	continue;
      }

      deflateReset(&p->zs);
      // TODO: set dictionary

      p->zs.next_out = qd->data;
      p->zs.avail_out = QUERY_DATA_BUFLEN;

      for (struct cli_out *o = query_cli.tx_pos; o; o = o->next) {
	p->zs.next_in = o->buf;
	p->zs.avail_in = o->wpos - o->buf;
	while (p->zs.avail_in > 0) {
	  int ds = deflate(&p->zs, Z_NO_FLUSH);

	  if (ds == Z_STREAM_ERROR) {
	    log(L_ERR "%s: deflate returned Z_STREAM_ERROR for prefix %I/%u", p->p.name, qnhn->prefix, qnhn->pxlen);
	    goto cleanup;
	  }

	  if (p->zs.avail_out == 0 || ds == Z_BUF_ERROR) {
	    qdd->length = QUERY_DATA_BUFLEN - p->zs.avail_out;
	    if (!(qdd = query_need_more_data(p, qdd)))
	      goto cleanup;

	    p->zs.next_out = qdd->data;
	    p->zs.avail_out = QUERY_DATA_BUFLEN;
	    continue;
	  }
	}
      }

      p->zs.avail_in = 0;
      p->zs.next_in = NULL;

      while (1) {
	int ds = deflate(&p->zs, Z_FINISH);
	if (ds == Z_STREAM_END) {
	  qdd->length = QUERY_DATA_BUFLEN - p->zs.avail_out;
	  break;
	}

	if (ds == Z_STREAM_ERROR) {
	  log(L_ERR "%s: deflate returned Z_STREAM_ERROR for prefix %I/%u", p->p.name, qnhn->prefix, qnhn->pxlen);
	  goto cleanup;
	}

	qdd->length = QUERY_DATA_BUFLEN - p->zs.avail_out;
	if (!(qdd = query_need_more_data(p, qdd)))
	  goto cleanup;

	p->zs.next_out = qdd->data;
	p->zs.avail_out = QUERY_DATA_BUFLEN;
      }

      cli_written(&query_cli);
      if (qdd->next) {
	query_free_chain(p, qdd->next);
	qdd->next = 0;
      }
    } else
      query_delete(p, qnhn->prefix, qnhn->pxlen);
    rem_node(&(qnhn->n));
    HASH_REMOVE(p->qnh, QNH, qnhn);
    sl_free(p->qnh_slab, qnhn);

    if (!--event_limit) {
      ev_schedule(p->qnh_event);
      goto cleanup;
    }
  }

cleanup:
  pthread_rwlock_unlock(&qn->h.lock);
  rfree(update_pool);
  return;
}

static void
query_rt_notify(struct proto *P, rtable *tbl UNUSED, net *n, rte *new UNUSED, rte *old UNUSED, ea_list *ea UNUSED)
{
  struct query_proto *p = (void *) P;
  struct query_net_hash_node *qnhn = HASH_FIND(p->qnh, QNH, n->n.pxlen, n->n.prefix);

  if (!qnhn) {
    qnhn = sl_alloc(p->qnh_slab);
    memset(qnhn, 0, sizeof(struct query_net_hash_node));
    *qnhn = (struct query_net_hash_node) { .pxlen = n->n.pxlen, .prefix = n->n.prefix, .born = now };
    HASH_INSERT2(p->qnh, QNH, P->pool, qnhn);
  }

  if (qnhn->born + 10 > now) {
    if (qnhn->n.next)
      rem_node(&(qnhn->n));

    add_tail(&(p->qnhq), &(qnhn->n));
  }

  ev_schedule(p->qnh_event);
}

static int 
query_shutdown(struct proto *P)
{
  struct query_proto *p = (void *) P;
  struct query_config *c = (void *) P->cf;

  deflateEnd(&p->zs);

  munmap(p->mem, c->size * sizeof(query_node));
  shm_unlink(c->shm);

  return PS_DOWN;
}

static int
query_start(struct proto *P)
{
  struct query_config *c = (void *) P->cf;
  struct query_proto *p = (void *) P;

  HASH_INIT(p->qnh, P->pool, QNH_INIT_ORDER);
  p->qnh_slab = sl_new(p->p.pool, sizeof(struct query_net_hash_node));
  p->qnh_event = ev_new(P->pool);
  p->qnh_event->hook = query_update_db;
  p->qnh_event->data = p;

  init_list(&(p->qnhq));

  p->zs = (z_stream) {
    .zalloc = NULL,
    .zfree = NULL,
    .opaque = NULL,
  };

  deflateInit(&p->zs, 9);
  // TODO: set dictionary

  p->fd = shm_open(c->shm, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
  if (p->fd == -1) {
    log(L_ERR "%s: Couldn't open shared memory: %M", P->name);
    return PS_START;
  }

  if (ftruncate(p->fd, c->size * sizeof(query_node)) < 0) {
    log(L_ERR "%s: Couldn't truncate shared memory to size %zu: %M", P->name, c->size * sizeof(query_node));
    shm_unlink(c->shm);
    return PS_START;
  }

  p->mem = mmap(NULL, c->size * sizeof(query_node), PROT_READ | PROT_WRITE, MAP_SHARED, p->fd, 0);
  if (p->mem == MAP_FAILED) {
    log(L_ERR "%s: Couldn't mmap shared memory: %M", P->name);
    shm_unlink(c->shm);
    return PS_START;
  }

  query_node *qn = p->mem;
  qn[0].type = QUERY_NODE_TYPE_HEADER;

  pthread_rwlockattr_init(&qn->h.lockattr);
  pthread_rwlockattr_setpshared(&qn->h.lockattr, PTHREAD_PROCESS_SHARED);
  pthread_rwlockattr_setkind_np(&qn->h.lockattr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
  pthread_rwlock_init(&qn->h.lock, &qn->h.lockattr);

  qn[1].l = (struct query_link) { .type = QUERY_NODE_TYPE_LINK };

  p->highest_node = 1;
  p->max_node = c->size - 1;
  p->qf_slab = sl_new(P->pool, sizeof(struct query_free_block));

  return PS_UP;
}

static struct proto *
query_init(struct proto_config *c)
{
  struct proto *P = proto_new(c, sizeof(struct query_proto));
  struct query_proto *p = (void *) P;

  p->fd = -1;

  P->accept_ra_types = RA_ANY;
  P->rt_notify = query_rt_notify;

  return P;
}

static int
query_reconfigure(struct proto *P, struct proto_config *new)
{
  struct query_proto *p = (void *) P;
  struct query_config *o = (void *) P->cf;
  struct query_config *n = (void *) new;

  return ((!strcmp(o->shm, n->shm)) && (o->size == n->size));
}

struct protocol proto_query = {
  .name =		"Query",
  .template =		"query%d",
  .preference =		0,
  .config_size =	sizeof(struct query_config),
  .init =		query_init,
  .start =		query_start,
  .shutdown =		query_shutdown,
  .reconfigure =	query_reconfigure,
};
