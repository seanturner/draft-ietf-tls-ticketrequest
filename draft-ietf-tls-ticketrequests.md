---
title: TLS Ticket Requests
abbrev: TLS Ticket Requests
docname: draft-ietf-tls-ticketrequests-latest
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: tpauly@apple.com
  -
    ins: D. Schinazi
    name: David Schinazi
    org: Google LLC
    street: 1600 Amphitheatre Parkway
    city: Mountain View, California 94043
    country: United States of America
    email: dschinazi.ietf@gmail.com
  -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net

normative:
  RFC2119:
  RFC8174:

--- abstract

TLS session tickets enable stateless connection resumption for clients without
server-side, per-client, state. Servers vend an arbitrary number of session tickets
to clients, at their discretion, upon connection establishment. Clients store and
use tickets when resuming future connections. This document describes a mechanism by
which clients can specify the desired number of tickets needed for future connections.
This extension aims to provide a means for servers to determine the number of tickets
to generate in order to reduce ticket waste, while simultaneously priming clients
for future connection attempts.

--- middle

# Introduction

As as described in {{!RFC8446}}, TLS servers vend clients an arbitrary
number of session tickets at their own discretion in NewSessionTicket messages.
There are at least three limitations with this design.

First, servers vend some (often hard-coded) number of tickets per
connection.  Some server implementations return a different default number of
tickets for session resumption than for the initial connection that created
the session.  No static choice, whether fixed, or resumption-dependent is ideal
for all situations.

Second, clients do not have a way of expressing their
desired number of tickets, which can impact future connection establishment.
For example, clients can open parallel TLS connections to the same server for HTTP,
or race TLS connections across different network interfaces. The latter is especially
useful in transport systems that implement Happy Eyeballs {{?RFC8305}}. Since clients control
connection concurrency and resumption, a standard mechanism for requesting more than one
ticket is desirable for avoiding ticket reuse. See {{!RFC8446}}, Appendix C.4 for discussion
of ticket reuse risks.

Third, all tickets in the client's possession
ultimately derive from some initial connection. Especially when the client
was initially authenticated with a client certificate, that session may need to
be refreshed from time to time. Consequently, a server may periodically
force a new connection even when the client presents a valid ticket.
When that happens, it is possible that any other tickets derived from the
same original session are equally invalid. A client avoids a full handshake
on subsequent connections if it replaces all stored tickets with
new ones obtained from the just performed full handshake. The number of
tickets the server should vend for a new connection may therefore need to be
larger than the number for routine resumption.

This document specifies a new TLS extension -- "ticket_request" -- that clients can
use to express their desired number of session tickets. Servers can use this
extension as a hint for the number of NewSessionTicket messages to vend.
This extension is only applicable to TLS 1.3 {{!RFC8446}},
DTLS 1.3 {{!I-D.ietf-tls-dtls13}}, and future versions of (D)TLS.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals,
as shown here.

# Use Cases

The ability to request one or more tickets is useful for a variety of purposes:

- Parallel HTTP connections: To improve performance, a client may open parallel connections.
To avoid ticket reuse, the client may use distinct tickets on each connection.
Clients must therefore bound the number of parallel connections they initiate by the number
of tickets in their possession, or risk ticket re-use.
- Connection racing: Happy Eyeballs V2 {{?RFC8305}} describes techniques for performing connection
racing. The Transport Services Architecture implementation from {{?TAPS=I-D.ietf-taps-impl}} also describes
how connections can race across interfaces and address families. In such cases, clients may use
more than one ticket while racing connection attempts in order to establish one successful connection.
Having multiple tickets equips clients with enough tickets to initiate connection racing while
avoiding ticket re-use and ensuring that their cache of tickets does not empty during such races.
Moreover, as some servers may implement single-use tickets, distinct tickets prevent
premature ticket invalidation by racing.
- Less ticket waste: Currently, TLS servers use application-specific, and often implementation-specific,
logic to determine how many tickets to issue. By moving the burden of ticket count to clients,
servers do not generate wasteful tickets. As an example, clients might only request one ticket during
resumption. Moreover, as ticket generation might involve expensive computation, e.g., public key
cryptographic operations, avoiding waste is desirable.
- Decline resumption: Clients can indicate they do not intend to resume a connection by
sending a ticket request with count of zero.

# Ticket Requests

As discussed in {{introduction}}, clients may want different numbers of tickets
for new or resumed connections. Clients may indicate to servers their desired
number of tickets to receive on a single connection, in the case of a new or
resumed connection, via the following "ticket_request" extension:

~~~
enum {
    ticket_request(TBD), (65535)
} ExtensionType;
~~~

Clients MAY send this extension in ClientHello. It contains the following structure:

~~~
struct {
    uint8 new_session_count;
    uint8 resumption_count;
} ClientTicketRequest;
~~~

new_session_count
: The number of tickets desired by the client if the server chooses to
negotiate a new connection.

resumption_count
: The number of tickets desired by the client if the server is willing to
resume using a ticket presented in this ClientHello.

A client starting a new connection SHOULD set new_session_count to the desired
number of session tickets and resumption_count to 0.
Once a client's ticket cache is primed, a resumption_count of 1 is a
good choice that allows the server to replace each ticket with a new ticket,
without over-provisioning the client with excess tickets. However, clients
which race multiple connections and place a separate ticket in each will
ultimately end up with just the tickets from a single resumed session.
In that case, clients can send a resumption_count equal to the number of
connections they are attempting in parallel. (Clients which send a resumption_count
less than the number of parallel connection attempts might end up with zero
tickets.)

When a client presenting a previously obtained ticket finds that the server
nevertheless negotiates a new connection, the client SHOULD assume that any
other tickets associated with the same session as the presented ticket are also
no longer valid for resumption.  This includes tickets obtained
during the initial (new) connection and all tickets subsequently obtained as
part of subsequent resumptions.  Requesting more than one ticket in cases when
servers complete a new connection helps keep the session cache primed.

Servers SHOULD NOT send more tickets than requested for the connection type
selected by the server (new or resumed connection). Moreover, servers
SHOULD place a limit on the number of tickets they are willing to send, whether
for new or resumed connections, to save resources.  Therefore, the
number of NewSessionTicket messages sent will typically be the minimum
of the server's self-imposed limit and the number requested.
Servers MAY send additional tickets, typically using the same limit, if
the tickets that are originally sent are somehow invalidated.

A server which supports and uses a client "ticket_request" extension MUST also send
the "ticket_request" extension in the EncryptedExtensions message. It contains
the following structure:

~~~
struct {
    uint8 expected_count;
} ServerTicketRequestHint;
~~~

expected_count
: The number of tickets the server expects to send in this connection.

Servers MUST NOT send the "ticket_request" extension in any handshake message, including
ServerHello or HelloRetryRequest messages. A client MUST abort the connection with an
"illegal_parameter" alert if the "ticket_request" extension is present in any server handshake
message.

If a client receives a HelloRetryRequest, the presence (or absence) of the "ticket_request" extension
MUST be maintained in the second ClientHello message. Moreover, if this extension is present, a client
MUST NOT change the value of ClientTicketRequest in the second ClientHello message.

# IANA Considerations

IANA is requested to create an entry, ticket_request(TBD), in the existing registry
for ExtensionType (defined in {{RFC8446}}), with "TLS 1.3" column values being set to
"CH, EE", and "Recommended" column being set to "Y".

# Performance Considerations

Servers can send tickets in NewSessionTicket messages any time after the
server Finished message (see {{RFC8446}}; Section 4.6.1). A server which
chooses to send a large number of tickets to a client
can potentially harm application performance if the tickets are sent before application data.
For example, if the transport connection has a constrained congestion window, ticket
messages could delay sending application data. To avoid this, servers should
prioritize sending application data over tickets when possible.

# Security Considerations

Ticket re-use is a security and privacy concern. Moreover, clients must take care when pooling
tickets as a means of avoiding or amortizing handshake costs. If servers do not rotate session
ticket encryption keys frequently, clients may be encouraged to obtain
and use tickets beyond common lifetime windows of, e.g., 24 hours. Despite ticket lifetime
hints provided by servers, clients SHOULD dispose of cached tickets after some reasonable
amount of time that mimics the session ticket encryption key rotation period.
Specifically, as specified in Section 4.6.1 of {{!RFC8446}}, clients MUST NOT cache tickets
for longer than 7 days.

In some cases, a server may send NewSessionTicket messages immediately upon sending
the server Finished message rather than waiting for the client Finished. If the server
has not verified the client's ownership of its IP address, e.g., with the TLS
Cookie extension (see {{RFC8446}}; Section 4.2.2), an attacker may take advantage of this behavior to create
an amplification attack proportional to the count value toward a target by performing a (DTLS) key
exchange over UDP with spoofed packets. Servers SHOULD limit the number of NewSessionTicket messages they send until they have verified the client's ownership of its IP address.

Servers that do not enforce a limit on the number of NewSessionTicket messages sent in response
to a "ticket_request" extension could leave themselves open to DoS attacks, especially if ticket
creation is expensive.

# Acknowledgments

The authors would like to thank David Benjamin, Eric Rescorla, Nick Sullivan, Martin Thomson,
Hubert Kario, and other members of the TLS Working Group for discussions on earlier versions of
this draft. Viktor Dukhovni contributed text allowing clients to send multiple
counts in a ticket request.
