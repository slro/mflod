# Crypto module

> This document is a part of **MFlod** messenger documentation which an
> implementation of **Flod** overlay protocol. For a complete version of
> project documentation see ???[no link yet].

This is a documentation for `Crypto` module of **MFlod** messenger. It describes
the process of creation of **Flod** protocol message packet, security
implications of a cryptographic design behind it and how all of this is
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
|            |          |             |
| (2) HEADER | (1) HMAC | (0) CONTENT |
|            |          |             |
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

Below is a more detailed description of content of each block of the message
packet.

#### (0) Content Block

The content block encapsulates the message being sent and time stamp of when it
was composed. Concatenated together they are encrypted with a uniformly at
random chosen encryption key (128 bit) of AES-128-CBC cipher.

The IV (128 bit) for AES-CBC encryption is also generated uniformly at random.
The concatenation of the time stamp and the message is padded with
[PKCS#7](https://en.wikipedia.org/wiki/Padding_(cryptography)) padding scheme.

The resulting `(0) CONTENT` block looks the following:

```
-----------------------------------------------------
|        | ...................................(100) |
|        | . ============================(10).      |
|   IV   | . || (1) time | (0) content ||    .      |
|        | . ============================    .      |
|        | ...................................      |
-----------------------------------------------------
```

To create a valid content block the following steps to be performed (omitting
ASN.1 aspects to simplify description):

 1. Get message to send from a user `(0)`
 2. Get current UTC time in a format `YYMMDDhhmmssZ` (complies with [ASN.1
    UTCtime type](https://www.obj-sys.com/asn1tutorial/node15.html)) `(1)`
 3. Concatenate `(1)` and `(0)` yielding `(1)|(0)`
 4. Pad `(1)|(0)` according to PKCS#7 standard to get block `(10)`. At this
    stage block `(10)` should be strictly a multiple of AES block size (which
    is 128 bit).
 5. Generate a random 128 bit bytestring which is an AES-128-CBC key for this
    message packet. The key generated is used **only 1 time** to encrypt the
    current message. Each new message must be encrypted with randomly generated
    fresh AES key.
 6. Generate a random 128 bit bytystring which is an initialization vector for
    this encryption procedure only. Each new message must be encrypted with
    randomly generated fresh IV.
