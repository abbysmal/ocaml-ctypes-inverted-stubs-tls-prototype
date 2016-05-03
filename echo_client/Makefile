BUILDDIR=../_build/echo_client
$(shell mkdir -p $(BUILDDIR))
OCAMLDIR=$(shell ocamlopt -where)

CC:= $(shell ocamlfind ocamlc -config | awk '/^bytecomp_c_compiler/ {for(i=2;i<=NF;i++) printf "%s " ,$$i}')
LD=$(CC)

all: $(BUILDDIR)/echo_client.native

clean:
	rm -rf $(BUILDDIR)

$(BUILDDIR)/echo_client.native: $(BUILDDIR)/echo_client.o
	$(LD) -o $@ $< -L$(BUILDDIR)/.. -ltls

$(BUILDDIR)/echo_client.o: echo_client.c
	$(CC) -c -o $@ -I $(OCAMLDIR) -I $(BUILDDIR)/../generated  $<

.PHONY: all clean
