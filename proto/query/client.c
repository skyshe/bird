/*
 * Build via this command:
 * gcc -std=gnu11 -o qcli -L$libdir -I$includedir -lbird-query client.c
 * where $libdir is where libbird-query.so resides
 * and $includedir is where bird-query.h resides
 *
 * Then run via this command:
 * LD_LIBRARY_PATH=$libdir ./qcli <shm name>
 *
 */

#include "bird-query.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: qcli <name> list of ipas\nor     cat ipa_list | qcli <name>");
    exit(2);
  }

  struct bird_query_handle *qh = bird_query_init(argv[1]);
  if (!qh) {
    printf("Failed bird query init: %s\n", bird_query_error);
    exit(1);
  }

  if (argc == 2) {
    char buf[256];
    while (fgets(buf, 255, stdin)) {
      char *x = buf;
      while (*x != '\n')
	x++;
      (*x) = 0;
      char *q = bird_query_find_all(qh, buf);
      if (q) {
	printf("%s\n", q);
	free((void *)q);
      } else {
	printf("FInd error: %s\n", bird_query_error);
      }
    }
  } else {
    for (int i=2; i<argc; i++) {
      char *q = bird_query_find_all(qh, argv[i]);
      if (q) {
	printf("%s\n", q);
	free((void *)q);
      } else {
	printf("Find error: %s\n", bird_query_error);
      }
    }
  }

  bird_query_cleanup(qh);
}
