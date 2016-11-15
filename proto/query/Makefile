source=query.c
root-rel=../../
dir-name=proto/query

qcli := lib

lib.o: CFLAGS+=-fPIC

source-dep := $(source) $(addsuffix .c,$(qcli))

subdir: $(addsuffix .o,$(qcli))

include ../../Rules
