/*
 *	BIRD -- Optimized query interface
 *
 *	(c) 2016 Jan Moskyto Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/query/query.h"

CF_DEFINES

#define QUERY_CFG ((struct query_config *) this_proto)

CF_DECLS

CF_KEYWORDS(QUERY, SHM, SIZE)

CF_GRAMMAR

CF_ADDTO(proto, query_proto '}')

query_proto_start: proto_start QUERY {
  this_proto = proto_config_new(&proto_query, $1);
};

query_proto:
   query_proto_start proto_name '{'
 | query_proto proto_item ';'
 | query_proto SHM TEXT ';' { QUERY_CFG->shm = $3; }
 | query_proto SIZE NUM ';' { QUERY_CFG->size = $3; }
 ;
