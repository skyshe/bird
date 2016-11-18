#ifndef _BIRD_QUERY_LIB_H_
#define _BIRD_QUERY_LIB_H_

#include <stdlib.h>

extern char *bird_query_error;

struct bird_query_handle *bird_query_init(const char *name);

char *bird_query_find(struct bird_query_handle *qh, const char *network);
char *bird_query_find_all(struct bird_query_handle *qh, const char *ip);

static inline void bird_query_free(char *data) { free((void *)data); }

void bird_query_cleanup(struct bird_query_handle *qh);

#endif
