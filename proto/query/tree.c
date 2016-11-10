#undef QUERY_TREE_CREATE_PATH
#undef QUERY_TREE_RETURN

#ifdef QUERY_TREE_FIND
#define QUERY_TREE_CREATE_PATH	0
#define QUERY_TREE_NOT_FOUND	NULL
#endif

#ifdef QUERY_TREE_GET
#define QUERY_TREE_CREATE_PATH	1
#define QUERY_TREE_NOT_FOUND	NULL
#endif

#ifdef QUERY_TREE_DELETE
#define QUERY_TREE_CREATE_PATH	0
#define QUERY_TREE_NOT_FOUND
#endif

#ifndef QUERY_TREE_CREATE_PATH
#error "QUERY_TREE_(FIND|GET|DELETE) not set!"
#endif

#ifdef QUERY_TREE_DELETE
  u32 *link_stack[(MAX_PREFIX_LENGTH/6) + 2] = {};
  u32 link_cnt = 0;
#endif

  uint pxlen_so_far = 0;
  u32 cur = 1;

  while (1) {
    if (pxlen - pxlen_so_far < 6) {
      u32 pxp = ipa_getbitrange(prefix, pxlen_so_far, pxlen - pxlen_so_far);
      u32 *wp = NULL;
      switch (pxlen - pxlen_so_far) {
	case 0:
	  wp = &(qn[cur].l.data0[0]);
	  break;
	case 1:
	  wp = &(qn[cur].l.data1[pxp]);
	  break;
	case 2:
	  wp = &(qn[cur].l.data2[pxp]);
	  break;
	case 3:
	  wp = &(qn[cur].l.data3[pxp]);
	  break;
	case 4:
	  wp = &(qn[cur].l.data4[pxp]);
	  break;
	case 5:
	  wp = &(qn[cur].l.data5[pxp]);
	  break;
      }
      
      if (*wp)
#ifdef QUERY_TREE_DELETE
      {
	query_free_chain(p, *wp);
	*wp = 0;
	qn[cur].l.count_data--;
	goto link_wipe;
      }
#else
	return &(qn[*wp].d);
#endif

#if !(QUERY_TREE_CREATE_PATH)
      return QUERY_TREE_NOT_FOUND;
#else

      *wp = query_alloc(p);
      if (!*wp)
	return QUERY_TREE_NOT_FOUND;

      qn[*wp].type = QUERY_NODE_TYPE_DATA;
      qn[cur].l.count_data++;
      return &(qn[*wp].d);
#endif
    } else {
      u32 pxp = ipa_getbitrange(prefix, pxlen_so_far, 6);
      u32 link = qn[cur].l.link[pxp];

      if (link & QUERY_LINK_TO_DATA_BIT) {
	link &= ~QUERY_LINK_TO_DATA_BIT;
	if (pxlen_so_far + 6 == pxlen)
#ifdef QUERY_TREE_DELETE
	{
	  query_free_chain(p, link);
	  qn[cur].l.link[pxp] = 0;
	  qn[cur].l.count_link--;
	  goto link_wipe;
	}
	else
	  return;
#else
	  return &(qn[link].d);
#endif

#if !(QUERY_TREE_CREATE_PATH)
	return QUERY_TREE_NOT_FOUND;
#else

	u32 newlink = query_alloc(p);
	if (!newlink)
	  return QUERY_TREE_NOT_FOUND;

	qn[newlink].type = QUERY_NODE_TYPE_LINK;
	qn[newlink].l.data0[0] = link;
	qn[newlink].l.count_data = 1;

	qn[cur].l.link[pxp] = newlink;

	pxlen_so_far += 6;
	cur = newlink;
	continue;
#endif
      }

      if (link) {
#ifdef QUERY_TREE_DELETE
	link_stack[link_cnt++] = &(qn[cur].l.link[pxp]);
#endif

	pxlen_so_far += 6;
	cur = link;
	continue;
      }

#if !(QUERY_TREE_CREATE_PATH)
      return QUERY_TREE_NOT_FOUND;
#else

      if (pxlen_so_far + 6 == pxlen) {
	u32 newdata = query_alloc(p);
	if (!newdata)
	  return QUERY_TREE_NOT_FOUND;

	qn[newdata].type = QUERY_NODE_TYPE_DATA;

	qn[cur].l.link[pxp] = newdata | QUERY_LINK_TO_DATA_BIT;
	qn[cur].l.count_link++;

	return &(qn[newdata].d);
      }

      u32 newlink = query_alloc(p);
      if (!newlink)
	return QUERY_TREE_NOT_FOUND;

      qn[newlink].type = QUERY_NODE_TYPE_LINK;

      qn[cur].l.link[pxp] = newlink;
      qn[cur].l.count_link++;

      pxlen_so_far += 6;
      cur = newlink;
      continue;
#endif
    }
  }
  return QUERY_TREE_NOT_FOUND;

#ifdef QUERY_TREE_DELETE
link_wipe:
  while (cur > 1 && (qn[cur].l.count_data == 0) && (qn[cur].l.count_link == 0)) {
    u32 *parent_link = link_stack[--link_cnt];
    query_free_node(p, cur);
    *parent_link = 0;
    cur = ((char *) parent_link - (char *) qn) / sizeof(query_node);
  }
#endif

#undef QUERY_TREE_FIND
#undef QUERY_TREE_GET
#undef QUERY_TREE_CREATE_PATH
#undef QUERY_TREE_DELETE
#undef QUERY_TREE_NOT_FOUND
