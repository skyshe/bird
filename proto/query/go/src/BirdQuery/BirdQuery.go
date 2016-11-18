package BirdQuery
// TODO: here should be set CFLAGS and LDFLAGS to link in the right way
//#include "bird-query.h"
import "C";

type BirdQuery struct {
  ptr *C.struct_bird_query_handle
}

type BirdQueryError struct {
  msg string
}

func (e BirdQueryError) Error() string {
  return e.msg
}

func Init(name string) (*BirdQuery, error) {
  var cname = C.CString(name)
  var p = C.bird_query_init(cname)
  if (p == nil) {
    return nil, BirdQueryError { msg: C.GoString(C.bird_query_error) }
  }

  return &BirdQuery { ptr: p }, nil
}

func (h *BirdQuery) Find(prefix string) (string, error) {
  var cpx = C.CString(prefix)
  var p = C.bird_query_find(h.ptr, cpx)
  if (p == nil) {
    return "", BirdQueryError { msg: C.GoString(C.bird_query_error) }
  }
  var str = C.GoString(p)
  C.bird_query_free(p)

  return str, nil
}

func (h *BirdQuery) FindAll(ip string) (string, error) {
  var cip = C.CString(ip)
  var p = C.bird_query_find_all(h.ptr, cip)
  if (p == nil) {
    return "", BirdQueryError { msg: C.GoString(C.bird_query_error) }
  }
  var str = C.GoString(p)
  C.bird_query_free(p)

  return str, nil
}

func (h *BirdQuery) Cleanup() {
  C.bird_query_cleanup(h.ptr)
}
