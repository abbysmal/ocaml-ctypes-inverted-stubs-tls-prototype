# Ctypes inverted stubs for OCaml-TLS

**Note**: This is a prototype and a work in progress. The interface will change and the code is still highly immature.

The goal of this project is to provide a binding to OCaml-TLS that can be called from C code.
More informations can be found on how inverted stubs works in [this repository](https://github.com/yallop/ocaml-ctypes-inverted-stubs-example.git) (providing a simple example on how to bind the Xmlm library).

This repository follow the same principles as the Xmlm inverted binding:

* [`bindings.ml`](lib/bindings.ml) uses ocaml-ctypes to define a C-compatible interface to ocaml-tls. Various functions are exposed to the C side to create a client configuration, and handle the TLS connection.

* [`generate.ml`](stub_generator/generate.ml) is an OCaml program that generates C source and header files from the definitions in the `Bindings` module, and an OCaml module that can be used to link the generated code with the code in `Bindings`.  (See [`apply_bindings.ml`](lib/apply_bindings.ml) for the actual linking.)

* [`echo_client.c`](echo_client/echo_client.c) is a simple TLS client written in C using the binding that will complete the TLS handshake and send messages on the resulting encrypted channel. Not complete right now.

**TODO**
* Finish the echo_client and write the associated echo_server code.
* Move the certificate configuration handling to the C side: currently this is handled in the OCaml code in a very … non-transparent fashion
* Various other things…
