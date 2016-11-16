source=query.c
root-rel=../../
dir-name=proto/query

libquery := lib

lib.o: CFLAGS+=-fPIC

source-dep := $(source) $(addsuffix .c,$(libquery))

subdir: $(addsuffix .o,$(libquery))

include ../../Rules
