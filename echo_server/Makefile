BUILDDIR=../_build/echo_server
$(shell mkdir -p $(BUILDDIR))
OCAMLDIR=$(shell ocamlopt -where)

CC:= $(shell ocamlfind ocamlc -config | awk '/^bytecomp_c_compiler/ {for(i=2;i<=NF;i++) printf "%s " ,$$i}')
LD=$(CC)

all: $(BUILDDIR)/echo_server.native

clean:
	rm -rf $(BUILDDIR)

$(BUILDDIR)/echo_server.native: $(BUILDDIR)/echo_server.o
	$(LD) -o $@ $< -L$(BUILDDIR)/.. -ltls

$(BUILDDIR)/echo_server.o: echo_server.c
	$(CC) -c -o $@ -I $(OCAMLDIR) -I $(BUILDDIR)/../generated  $<

.PHONY: all clean
