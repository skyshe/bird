#include "lib.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: qcli <name> list of ipas\n");
    exit(2);
  }

  struct query_handle *qh = query_init(argv[1]);

  if (argc == 2) {
    char buf[256];
    while (fgets(buf, 255, stdin)) {
      char *x = buf;
      while (*x != '\n')
	x++;
      (*x) = 0;
      const char *q = query_find_all(qh, buf);
      if (q) {
	printf("%s\n", q);
	free((void *)q);
      } else {
	printf("Parse error.\n");
      }
    }
  }

  for (int i=2; i<argc; i++) {
    const char *q = query_find_all(qh, argv[i]);
    if (q) {
      printf("%s\n", q);
      free((void *)q);
    } else {
      printf("Parse error.\n");
    }
  }
}
