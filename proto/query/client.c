#include "nest/bird.h"
#include "proto/query/data.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

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

struct query_data *
query_find(query_node *qn, ip_addr prefix, uint pxlen) {

#define QUERY_TREE_FIND
#include "tree.c"
}

static int qnfd = -1;

query_node *
query_init(const char *name) {
  qnfd = shm_open(name, O_RDWR, 0);
  if (qnfd == -1) {
    perror("open");
    exit(1);
  }

  struct stat st;
  if (fstat(qnfd, &st)) {
    perror("fstat");
    exit(1);
  }

  void *mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, qnfd, 0);
  if (mem == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  return mem;
}

z_stream zs = {};

void work(query_node *qn, ip_addr a) {
  pthread_rwlock_rdlock(&qn->h.lock);
  printf("Locked.\n");
  fflush(stdin);
  for (uint pxlen = MAX_PREFIX_LENGTH; pxlen; pxlen--) {
    struct query_data *qd = query_find(qn, a, pxlen);
    if (!qd) continue;
    char buf[256];
    int n = bsprintf(buf, "Found data for %I/%d: %p", ipa_and(a, ipa_mkmask(pxlen)), pxlen, qd);
    puts(buf);

    zs.next_in = qd->data;
    zs.avail_in = qd->length;
    zs.next_out = buf;
    zs.avail_out = 256;
    int flush = Z_NO_FLUSH;
    while (1) {
      int is = inflate(&zs, flush);

      if (is == Z_STREAM_END) {
	fwrite(buf, 1, 256 - zs.avail_out, stdout);
	break;
      }

      if (is != Z_OK) {
	printf("Error inflating query data: %s\n", zs.msg);
	pthread_rwlock_unlock(&qn->h.lock);
	exit(1);
      }

      if (zs.avail_out == 0) {
	fwrite(buf, 1, 256, stdout);
	zs.next_out = buf;
	zs.avail_out = 256;
	continue;
      }

      if (zs.avail_in == 0) {
	if (qd->next) {
	  qd = &(qn[qd->next].d);
	  zs.next_in = qd->data;
	  zs.avail_in = qd->length;
	} else
	  flush = Z_FINISH;

	continue;
      }
    }
    inflateReset(&zs);

  }
  pthread_rwlock_unlock(&qn->h.lock);
  printf("Unlocked.\n");
  fflush(stdin);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: qcli <name> list of ipas\n");
    exit(2);
  }
  query_node *qn = query_init(argv[1]);

  inflateInit(&zs);

  ip_addr a;
  if (argc == 2) {
    char buf[256];
    while (fgets(buf, 255, stdin)) {
      char *x = buf;
      while (*x != '\n')
	x++;
      (*x) = 0;
      if (!ipa_pton(buf, &a)) {
	printf("Error parsing IP %s.\n", buf);
	continue;
      }
      work(qn, a);
    }
  }
  for (int i=2; i<argc; i++) {
    if (!ipa_pton(argv[i], &a)) {
      printf("Error parsing IP %s.\n", argv[i]);
      continue;
    }
    work(qn, a);
  }
}
