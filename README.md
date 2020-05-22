# Sodium TCP blueprint
This project is the outcome of some research. It provides some blueprint/boilerplate code on how to design a TCP protocol with performance and security in mind. As the complete TCP payload is *encrypted* starting with the *1st* packet, a detection by **D**eep **P**acket **I**nspection engines isn't as easy as for some proprietary and non-proprietary TCP based layer 7 protocols. Three things you'll need to successfully connect to a remote: servers public key, username and password. The latter ones could be replaced by something else e.g. an authentication token. But this is out of scope for this blueprint.
It is tied to *libsodium* as cryptographic foundation and *libevent* for event based network IO.
However, with some manageable effort *libevent* integration could be replaced by something else since the core functionality is IO-agnostic.

# build
see `make help` for configure options

Example:
use `make ENABLE_DEBUG=y ENABLE_SANITIZER=y ENABLE_SHARED=y`

to build client/server with:
 * verbose debug logging
 * ASAN, LSAN and UBSAN enabled
 * build shared code used by client and server as shared library

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
Simple REQUEST/RESPONSE based binary protocol. A **P**rotocol **D**ata **U**nit typically contains a header (*struct protocol_header*) and a body (e.g. *struct protocol_data*).
The type of a **PDU** is determined in the header. Same goes for the total size of the body.
Separating a **PDU** into header and body is necessary for stream ciphers provided by *libsodium*.
I wasn't able to find a more comfortable way for **PDU** encryption/decryption handling. Maybe you will? ;)
