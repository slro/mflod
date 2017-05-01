# Crypto module

> This document is a part of **MFlod** messenger documentation which an
> implementation of **Flod** overlay protocol. For a complete version of
> project documentation see ???[no link yet].

This is a documentation for a `Crypto` module of **MFlod** messenger. It describes
the process of creation of **Flod** protocol message packet, security
implications of the cryptographic design behind it and how all of this is
implemented in **MFlod**.

## Description of a message packet structure

The message packet is a structure that represents an encrypted message that is
sent from a one user of **Flod** protocol overlay to an other. The size of the
packet can be of variable length though some of its parts are always remain
constant.

The general structure of the message packet is described below together with
some security implications while the further sections describe how a general
packet structure is expressed in terms of ASN.1 which is what actually used in
a reference implementation.

### General Structure

In essence the message packet structure is very similar to a standard [hybrid
cryptosystem scheme](https://en.wikipedia.org/wiki/Hybrid_cryptosystem). The
illustration below is a high-level overview of **Flod** message packet:

```
---------------------------------------
|                                     |
| (2) HEADER | (1) HMAC | (0) CONTENT |
|                                     |
---------------------------------------
```

The indices from right to left are motivated by the order in which message packet
is constructed. The basic description of the each block is as follows:

 - `(0) CONTENT` - encrypted with AES-128-CBC timestamped message with
     prepended plaintext IV (initialization vector).
 - `(1) HMAC` - hash-based message authentication code of a
     `(0)` block. The underlying hash function is SHA-1.
 - `(2) HEADER` - encrypted with public key of a recipient with RSA-OAEP
     meta-information about a message along with keys generated for blocks
     `(0)` and `(1)`.

Below is more detailed description of contents of an each block of the message
packet.

#### (0) Content Block

Hey hey hey
