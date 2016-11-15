#ifndef _BIRD_QUERY_LIB_H_
#define _BIRD_QUERY_LIB_H_

struct query_handle *query_init(const char *name);

const char *query_find(struct query_handle *qh, const char *network);
const char *query_find_all(struct query_handle *qh, const char *ip);

void query_cleanup(struct query_handle *qh);

#endif
