#ifndef _BIRD_QUERY_LIB_H_
#define _BIRD_QUERY_LIB_H_

struct bird_query_handle *bird_query_init(const char *name);

const char *bird_query_find(struct bird_query_handle *qh, const char *network);
const char *bird_query_find_all(struct bird_query_handle *qh, const char *ip);

void bird_query_cleanup(struct bird_query_handle *qh);

#endif
