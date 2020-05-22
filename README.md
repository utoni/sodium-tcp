# Sodium TCP blueprint
This project is the outcome of some research. It provides some blueprint/boilerplate code on how to design a TCP protocol with performance and security in mind. As the complete TCP payload is encrypted starting with the *1st* packet, a detection by **D**eep **P**acket **I**nspection engines isn't as easy as for many other proprietary or non-proprietary TCP protocols.
It is tied to *libsodium* as cryptographic foundation and *libevent* for event based network IO. However, it should be easy to replace the *libevent* integration with something else.

# build
see `make help` for configure options

Example:
use `make ENABLE_DEBUG=y ENABLE_SANITIZER=y ENABLE_SHARED=y`

to build client/server with:
 * verbose debug logging
 * with ASAN, LSAN and UBSAN support
 * build code used by both, client/server, as shared library

# run
generate a private/public keypair: `./server`
use that key: `./server -k [ServerPrivateKey]`
connect to the server as client: `./client -k [ServerPublicKey]`

other useful client/server command line arguments:
 * `-h` set remote/listen host
 * `-p` set remote/listen port
 * `-f` set filepath to read/write from/to

Example:
`./server -k [ServerPrivateKey] -f /tmp/received_file`
`./client -k [ServerPublicKey] -f /tmp/file_to_send`

Send a file over the wire (client -> server).
It is possible to use *FIFO*s as well for `-f`.

## Warning
The provided code should **not** used in production environments without further testing!

## Protocol
Simple REQUEST/RESPONSE based binary protocol. A **P**rotocol **D**ata **U**nit typically contains of a header (*struct protocol_header*) and a body (e.g. *struct protocol_data*).
The type of **PDU** is determined in the header as well the total size of the body.

