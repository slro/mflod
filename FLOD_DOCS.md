FLOD Overlay Communication Protocol
===================================

Abstract
--------

This document specifies **FLOD protocol** for secure online communication over the
Internet. The purpose and the scope of this memo is to provide a detailed
description of the protocol design as well as an overview of possible use cases
of it for communication over insecure channels.

Index
-----

1. [Introduction](#introducation)
    1. [Motivation](#motivation)
    2. [Main concepts](#main-concepts)

Introduction
------------

### Motivation

Over the last years a numerous messengers appeared that claim to be provide
a completely confidential and secure way of communication. The main features
they advertise are usually *end-to-end encryption* and (occasionally)
*decentralized architecture*.

While the above mentioned features are a valuable addition to ensure
communication security in general, they all focus on availability and
information concealing while leaking all kinds of *meta-information*.

The main motivation affecting **FLOD** protocol design decisions is a requirement
to provide a best effort attempt to hide any information about communicating
parties.

This involves concealing of plain text data, communication patterns,
location information while leaving a way for parties to authenticate the
identities of each other.

### Main Concepts


