#include "nest/bird.h"
#include "proto/query/lib.h"
#include "proto/query/data.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct query_handle {
  query_node *qn;
  size_t len;
  z_stream zs;
  int fd;
};

struct query_handle *query_init(const char *name) {
  struct query_handle *qh = malloc(sizeof(struct query_handle));
  if (!qh) {
    perror("malloc");
    return NULL;
  }

  qh->zs = (z_stream) {};
  inflateInit(&(qh->zs));

  qh->fd = shm_open(name, O_RDWR, 0);
  if (qh->fd == -1) {
    free(qh);
    perror("open");
    return NULL;
  }

  struct stat st;
  if (fstat(qh->fd, &st)) {
    close(qh->fd);
    free(qh);
    perror("fstat");
    return NULL;
  }

  qh->len = st.st_size;

  qh->qn = mmap(NULL, qh->len, PROT_READ | PROT_WRITE, MAP_SHARED, qh->fd, 0);
  if (qh->qn == MAP_FAILED) {
    close(qh->fd);
    free(qh);
    perror("mmap");
    return NULL;
  }

  return qh;
}

void query_cleanup(struct query_handle *qh) {
  munmap(qh->qn, qh->len);
  close(qh->fd);
  free(qh);
}

static struct query_data *
query_find_internal_(query_node *qn, ip_addr prefix, uint pxlen) {
#define QUERY_TREE_FIND
#include "tree.c"
}

static inline char *
query_find_internal(struct query_handle *qh, char *buf, int *pos, int *total, ip_addr prefix, uint pxlen) {
  struct query_data *qd = query_find_internal_(qh->qn, prefix, pxlen);
  if (!qd)
    return buf;

  qh->zs.next_in = qd->data;
  qh->zs.avail_in = qd->length;
  qh->zs.next_out = buf + *pos;
  qh->zs.avail_out = *total - *pos - 1;
  int flush = Z_NO_FLUSH;
  while (1) {
    int is = inflate(&(qh->zs), flush);

    if (is == Z_STREAM_END) {
      *pos = *total - qh->zs.avail_out;
      inflateReset(&(qh->zs));
      return buf;
    }

    if (is != Z_OK) {
      fprintf(stderr, "Error inflating query data: %s\n", qh->zs.msg);
      inflateReset(&(qh->zs));
      return NULL;
    }

    if (qh->zs.avail_out == 0) {
      buf = realloc(buf, *total*2);

      qh->zs.avail_out = *total-1;
      qh->zs.next_out = buf + *total;

      *total *= 2;
      continue;
    }

    if (qh->zs.avail_in == 0) {
      if (qd->next) {
	qd = &(qh->qn[qd->next].d);
	qh->zs.next_in = qd->data;
	qh->zs.avail_in = qd->length;
      } else
	flush = Z_FINISH;

      continue;
    }
  }
}

const char *query_find(struct query_handle *qh, const char *network) {
  const char *slash = strchr(network, '/');

  int pxlen;
  if (sscanf(slash+1, "%u", &pxlen) != 1)
    return NULL;

  ip_addr prefix;
  char ipabuf[256];
  memcpy(ipabuf, network, slash-network);
  ipabuf[slash-network] = 0;
  if (!ipa_pton(ipabuf, &prefix))
    return NULL;

  int outsize = 1024;
  int pos = 0;
  char *out = malloc(outsize);

  pthread_rwlock_rdlock(&qh->qn->h.lock);
  out = query_find_internal(qh, out, &pos, &outsize, prefix, pxlen);
  pthread_rwlock_unlock(&qh->qn->h.lock);

  out[pos] = 0;
  return out;
}

const char *query_find_all(struct query_handle *qh, const char *ip) {
  ip_addr prefix;
  if (!ipa_pton(ip, &prefix))
    return NULL;

  int outsize = 1024;
  int pos = 0;
  char *out = malloc(outsize);

  pthread_rwlock_rdlock(&qh->qn->h.lock);
  for (int pxlen = MAX_PREFIX_LENGTH; pxlen >= 0; pxlen--)
    out = query_find_internal(qh, out, &pos, &outsize, prefix, pxlen);
  pthread_rwlock_unlock(&qh->qn->h.lock);

  out[pos] = 0;
  return out;
}

void
bug(const char *msg, ...)
{
  va_list args;

  va_start(args, msg);
  fputs("Internal error: ", stderr);
  vfprintf(stderr, msg, args);
  va_end(args);
  exit(1);
}

