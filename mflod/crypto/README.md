Crypto module
=============

> This document is a part of **MFlod** messenger documentation which is an
> implementation of **Flod** overlay protocol. For a complete version of
> project documentation see [no link yet]. [TODO: add link]

This is a documentation for `Crypto` module of **MFlod** messenger. It describes
the process of creation of **Flod** protocol message packet, security
implications of a cryptographic design behind it and how all of these is
implemented in **MFlod**.

Table of Contents
-----------------

 1. [Message Packet Structure](#message-packet-structure)
    1. [General Structure](#general-structure)
       * [`(0) CONTENT` Block](#0-content-block)
       * [`(1) HMAC` Block](#1-hmac-block)
       * [`(2) HEADER` Block](#2-header-block)
    2. [ASN.1 Backed Structure](#asn1-backed-structure)

Message Packet Structure
-----------------------------------------

The message packet is a structure that represents an encrypted message that is
sent from one user of **Flod** protocol overlay to another. The size of the
packet can be of variable length though some of its parts are always remain
constant (`(1) HMAC` block, local blocks of `(2) HEADER` etc). 

A general structure of the message packet is described below together with
some security implications while further sections describe how the general
message packet structure is expressed in terms of ASN.1 which is enforced by 
**Flod** protocol documentation.

### General Structure

> The general structure documentation section is intended as a description of
> the message packet creation logic. It should not be used on its own to
> implement the message packet assembler. A section on
> [ASN.1 backed structure](#asn1-backed-structure)
> is what to be used as an actual implementation reference.

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

The indices from right to left are motivated by the order in which message
packet is constructed. A basic description of each block is as follows:

 - `(0) CONTENT` - encrypted with AES-128-CBC timestamped message with
     prepended plaintext IV (initialization vector).
 - `(1) HMAC` - hash-based message authentication code of a
     `(0)` block. The underlying hash function is SHA-1.
 - `(2) HEADER` - encrypted with public key of a recipient using RSA-OAEP
     encryption algorithm meta-information about a message along with keys
     generated for blocks `(0)` and `(1)`.

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
---------------------------------------------------
|        | .................................(100) |
|        | . **************************(10).      |
|   IV   | . * (1) time | (0) content *    .      |
|        | . **************************    .      |
|        | .................................      |
---------------------------------------------------
```

To create a valid content block the following steps to be performed (omitting
ASN.1 aspects to simplify the initial description):

 1. Get message to send from a user `(0)`
 2. Get current UTC time in a format `YYMMDDhhmmssZ` (complies with [ASN.1
    UTCTime type](https://www.obj-sys.com/asn1tutorial/node15.html)) `(1)`
 3. Concatenate `(1)` and `(0)` yielding `(1)|(0)`
 4. Pad `(1)|(0)` according to PKCS#7 standard to get block `(10)`. At this
    stage block `(10)` should be strictly a multiple of AES block size (which
    is 128 bit).
 5. Generate a random 128 bit value which is an AES-128-CBC key for this
    message packet. The key generated is used **only 1 time** to encrypt the
    current message only. Each new message must be encrypted with randomly 
    generated fresh AES key.
 6. Generate a random 128 bit value which is an initialization vector for
    this encryption procedure only. Each new message must be encrypted with
    randomly generated fresh IV.
 7. Encrypt block `(10)` with AES-128 in [CBC
    mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) using
    the key and the IV generated during steps 5-6. The result is a block
    `(100)`.
 8. Prepend block `(100)` with IV used for encryption (generated on step 6).
    After that the full `(0) CONTENT` block was constructed.

The reason why AES-128 was chosen over AES-256 is due to a poor design of a key
schedule for a later flavor of AES (see [this
article](https://www.schneier.com/blog/archives/2009/07/another_new_aes.html)).

#### (1) HMAC Block

This block encapsulates a hash-based message authentication code for the block
`(0) CONTENT`. The hash function of choice is SHA-1 and despite recent news of
[Google breaking
it](https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html)
HMAC bases on SHA-1 is still secure (see
[[1]](http://www.schneier.com/blog/archives/2005/02/sha1_broken.html),
[[2]](http://cseweb.ucsd.edu/~mihir/papers/hmac-new.html),
[[RFC2104, page 5]](https://www.ietf.org/rfc/rfc2104.txt)).

To produce a correct HMAC for a block `(0) CONTENT` the following steps are
necessary:

 1. Generate a random 160 bit bytestring which is a key to use for this HMAC
    calculation. Every new message must utilize a random and fresh HMAC key.
 2. Calculate an SHA1-HMAC of `(0) CONTENT` block with a key from step 1. The
    result is the `(1) HMAC` block.

#### (2) Header Block

The header block is an encrypted container for keys used in previous blocks as
well as some extra meta-information that facilitates protocol operation. 

The encryption is performed using RSA algorithm with a key length at least 1024 bit.
The content of a block is padded with
[OAEP](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding).

The structure is as follows:

```
-------------------------------------------------------------------------------------
|******************************************************************************(200)|
|*        |          | +++++++++++++++++++++++++(20) |            |           *     |
|* (4) IS | (3) S_ID | + (2) H(k_hmac | k_aes) +     | (1) K_HMAC | (0) K_AES *     |
|*        |          | +++++++++++++++++++++++++     |            |           *     |
|******************************************************************************     |
-------------------------------------------------------------------------------------
```

These steps are necessary to produce a valid header block:

 1. Concatenate keys that were used in `(1) HMAC` block and `(0) CONTENT`
    blocks. The first one is the key used to calculate an HMAC. The second one
    is a key used in AES encryption. The local blocks `(1)` and `(0)` are ready.
 2. Calculate a SHA-1 hash from the result of step 1. This yields a local block
    `(2)`.
 3. Sign local block `(2)` produced in the previous step with RSA private key
    of a sender. The signature is a local block `(20)`. Prepend result of the
    step 1 with the it.
 4. Prepend the result of the previous step with a PGP keypair ID `(3)` of a 
    sender. If the sender's keypair is not a PGP keypair append all-zero dummy ID. 
 5. Prepend the result of the previous step with a 4-byte indentification
    string `(4)`: *FLOD*. This value is used to determine a successful decryption
    of a header block on a side of the recipient.
 6. Pad result of the previous step according to 
    [OAEP](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
    padding standard
 7. Encrypt the result of the previous step with RSA using public key of the
    recipient. The result is a local block `(200)` and itself is a full
    `(2) HEADER` block.

Note that *steps 2-4 are optional* and can be omitted depending on a sender's
decision. Though it would not allow the recipient to verify the identity of the
sender in any way. It still allows the recipient to decrypt a message.

The minimal required size of RSA keypair for both sender and recipient is
1024 bits. The recommended size of RSA keypair is at least 2048 bits.

In case of a usage of PGP RSA keypairs the actual public and secret key
information must be extracted from PGP containers. The signature creation and
encryption routines **cannot be preformed** by PGP software suit. The reason
for it is a leakage of meta-information about a keypair owner in PGP software
(ID, email etc).

### ASN.1 Backed Structure
