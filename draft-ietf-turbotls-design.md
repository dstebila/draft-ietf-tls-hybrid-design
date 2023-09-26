---
title: TurboTLS for faster connection establishment
abbrev: ietf-turbotls-design
docname: draft-ietf-turbotls-design-latest
date: 2023-09-05
category: info

? ipr: trust200902
keyword: Internet-Draft

? stand_alone: yes
? pi: [toc, sortrefs, symrefs]

submissionType: IETF

author:
  -
    ins: D. Stebila
    name: Douglas Stebila
    organization: University of Waterloo
    email: dstebila@uwaterloo.ca
  -
    ins: D. Joseph
    name: David Joseph
    organization: SandboxAQ 
    email: dj@sandboxaq.com
  -
    ins: C. Aguilar-Melchor
    name: Carlos Aguilar-Melchor
    organization: SandboxAQ
    email: carlos.aguilar@sandboxaq.com

  -
    ins: J. Goertzen
    name: Jason Goertzen
    organization: SandboxAQ
    email: jason.goertzen@sandboxquantum.com

normative:
  TLS13: RFC8446
  TLS12: RFC5246
  UDP: RFC768
  TCP: RFC793

informative:
  AVIRAM:
    target: https://mailarchive.ietf.org/arch/msg/tls/F4SVeL2xbGPaPB2GW_GkBbD_a5M/
    title: "[TLS] Combining Secrets in Hybrid Key Exchange in TLS 1.3"
    date: 2021-09-01
    author:
      -
        ins: Nimrod Aviram
      -
        ins: Benjamin Dowling
      -
        ins: Ilan Komargodski
      -
        ins: Kenny Paterson
      -
        ins: Eyal Ronen
      -
        ins: Eylon Yogev
  BCNS15: DOI.10.1109/SP.2015.40
  BERNSTEIN: DOI.10.1007/978-3-540-88702-7
  BINDEL: DOI.10.1007/978-3-030-25510-7_12
  CAMPAGNA: I-D.campagna-tls-bike-sike-hybrid
  CECPQ1:
    target: https://security.googleblog.com/2016/07/experimenting-with-post-quantum.html
    title: Experimenting with Post-Quantum Cryptography
    author:
      -
        ins: M. Braithwaite
    date: 2016-07-07
  CECPQ2:
    target: https://www.imperialviolet.org/2018/12/12/cecpq2.html
    title: CECPQ2
    author:
      -
        ins: A. Langley
    date: 2018-12-12
  DODIS: DOI.10.1007/978-3-540-30576-7_11
  DOWLING: DOI.10.1007/s00145-021-09384-1
  ETSI:
    target: https://www.etsi.org/images/files/ETSIWhitePapers/QuantumSafeWhitepaper.pdf
    title: "Quantum safe cryptography and security: An introduction, benefits, enablers and challengers"
    author:
      -
        role: editor
        ins: M. Campagna
      -
        ins: others
    seriesinfo: ETSI White Paper No. 8
    date: 2015-06
  EVEN: DOI.10.1007/978-1-4684-4730-9_4
  EXTERN-PSK: RFC8773
  FLUHRER:
    target: https://eprint.iacr.org/2016/085
    title: "Cryptanalysis of ring-LWE based key exchange with key share reuse"
    author:
      -
        ins: S. Fluhrer
    seriesinfo: Cryptology ePrint Archive, Report 2016/085
    date: 2016-01
  FO: DOI.10.1007/s00145-011-9114-1
  FRODO: DOI.10.1145/2976749.2978425
  GIACON: DOI.10.1007/978-3-319-76578-5_7
  HARNIK: DOI.10.1007/11426639_6
  HHK: DOI.10.1007/978-3-319-70500-2_12
  HPKE: RFC9180
  IKE-HYBRID: I-D.tjhai-ipsecme-hybrid-qske-ikev2
  IKE-PSK: RFC8784
  KIEFER: I-D.kiefer-tls-ecdhe-sidh
  Kyber:
    target: https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Kyber-Round3.zip
    title: Crystals-Kyber NIST Round 3 submission
    author:
      -
        ins: Roberto Avanzi, Joppe Bos, Léo Ducas, Eike Kiltz, Tancrède Lepoint, Vadim Lyubashevsky, John M. Schanck, Peter Schwabe, Gregor Seiler, Damien Stehlé
    date: 2020-10-01
  LANGLEY:
    target: https://www.imperialviolet.org/2018/04/11/pqconftls.html
    title: Post-quantum confidentiality for TLS
    author:
      -
        ins: A. Langley
    date: 2018-04-11
  LUCKY13:
    target: https://ieeexplore.ieee.org/iel7/6547086/6547088/06547131.pdf
    title: "Lucky Thirteen: Breaking the TLS and DTLS record protocols"
    author:
    -
      ins: N. J. Al Fardan
    -
      ins: K. G. Paterson
  NIELSEN:
    title: Quantum Computation and Quantum Information
    author:
      -
        ins: M. A. Nielsen
      -
        ins: I. L. Chuang
    seriesinfo: Cambridge University Press
    date: 2000
  NIST:
    target: https://www.nist.gov/pqcrypto
    title: Post-Quantum Cryptography
    author:
      org: National Institute of Standards and Technology (NIST)
  NIST-FIPS-202:
    target: https://doi.org/10.6028/NIST.FIPS.202
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    author:
      org: National Institute of Standards and Technology (NIST)
    date: 2015-08
  NIST-SP-800-56C:
    target: https://doi.org/10.6028/NIST.SP.800-56Cr2
    title: Recommendation for Key-Derivation Methods in Key-Establishment Schemes
    author:
      org: National Institute of Standards and Technology (NIST)
    date: 2020-08
  NIST-SP-800-135:
    target: https://doi.org/10.6028/NIST.SP.800-135r1
    title: Recommendation for Existing Application-Specific Key Derivation Functions
    author:
      org: National Institute of Standards and Technology (NIST)
    date: 2011-12
  OQS-102:
    target: https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_0_2-stable
    title: OQS-OpenSSL-1-0-2_stable
    author:
      org: Open Quantum Safe Project
    date: 2018-11
  OQS-111:
    target: https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable
    title: OQS-OpenSSL-1-1-1_stable
    author:
      org: Open Quantum Safe Project
    date: 2022-01
  OQS-PROV:
    target: https://github.com/open-quantum-safe/oqs-provider/
    title: OQS Provider for OpenSSL 3
    author:
      org: Open Quantum Safe Project
    date: 2023-07
  PST: DOI.10.1007/978-3-030-44223-1_5
  RACCOON:
    target: https://raccoon-attack.com/
    title: "Raccoon Attack: Finding and Exploiting Most-Significant-Bit-Oracles in TLS-DH(E)"
    author:
    -
      ins: R. Merget
    -
      ins: M. Brinkmann
    -
      ins: N. Aviram
    -
      ins: J. Somorovsky
    -
      ins: J. Mittmann
    -
      ins: J. Schwenk
    date: 2020-09
  S2N:
    target: https://aws.amazon.com/blogs/security/post-quantum-tls-now-supported-in-aws-kms/
    title: Post-quantum TLS now supported in AWS KMS
    author:
      org: Amazon Web Services
    date: 2019-11-04
  SCHANCK: I-D.schanck-tls-additional-keyshare
  WHYTE12: I-D.whyte-qsh-tls12
  WHYTE13: I-D.whyte-qsh-tls13
  XMSS: RFC8391
  ZHANG: DOI.10.1007/978-3-540-24632-9_26

--- abstract

This document provides a protocol definition for handshaking over UDP in the Transport Layer Security (TLS) protocol (version independent). In parallel, a TCP session is established, and once this is done, the TLS session reverts to TCP. In the event that the UDP handshaking portion fails, TurboTLS falls back to TLS-over-TCP as is usually done, resulting in negligible latency cost in the case of failure. The document also describes a mechanism for maximising UDP-TLS-handshake compatibility with middleboxes, known as _request-based-fragmentation_

Discussion of this work is encouraged to happen on the TLS IETF mailing list tls@ietf.org or on the GitHub repository which contains the draft: https://github.com/PhDJsandboxaq/draft-ietf-turbotls-design/.

--- middle

# Introduction {#introduction}

This document gives a construction for TurboTLS, which at its core is a method for handshaking over UDP in TLS before switching back to TCP for the TLS session. A technique called client request-based fragmentation is described to reduce the possibility of portions of the handshake over UDP being filtered by poorly configured middle-boxes, and a fallback procedure to standard TLS-over-TCP (at minimal latency overhead) is provided.



## Terminology {#terminology}

UDP
TCP
TLS
QUIC
DNS
connection-based protocol
connectionless protocol


## Motivation for handshaking over UDP {#motivation}
TLS is the most ubiquitous application layer security protocol in use at the time of writing. Other protocols for secure connection establishment have been proposed, and one such widely-used protocol is QUIC. QUIC runs entirely over UDP and merges the transport and security aspects into one specification, handling packet loss, reordering, handshake establishment, and session management all in one protocol. One benefit of QUIC is that it enjoys fast connection establishment because it runs over UDP, whereas running on TCP would mean waiting for a TCP handshake to occur which requires one round trip.

Many will make the choice to move from TLS to QUIC, however some will not for a range of reasons. Deep packet inspection is inhibited in QUIC, and updating some legacy systems can be difficult. TurboTLS aims to provide a method for those who do not want to fully switch to QUIC, to benefit from the fast connection establishment enabled by UDP, but without fundamentally changing the security properties of TLS, and furthermore enabling implementation via transparent proxying, thus avoiding the need to directly upgrade such systems themselves.



## Scope {#scope}

This document focuses on TurboTLS. It covers everything needed to achieve the handshaking portion of a TLS connection over UDP, including

- **Construction in principle:** It provides an outline of which flows are sent over UDP, which are sent over TCP and in what order.
  
- **TLS-over-TCP fallback:** The document describes what to do in the case of failure due to UDP packet loss or filtering. The scheme should revert to TLS-over-TCP incurring a small latency overhead that should be minimal in comparison with standard TLS-over-TCP without a TurboTLS attempt.
  
- **Client request-based fragmentation:** Due to the impact of post-quantum cryptography such as larger keys certain considerations have to be taken into account. One is that a Server Hello is likely to require multiple UDP packets, thus to eliminate the possibility of reflection attacks and failures due to middle-box filtering, we describe how to create a one-to-one correspondence between Client Hello packets and Server Hello packets.
  
- **How to implement via a transparent proxy:** The document gives a brief description of how one can implement TurboTLS via a transparent proxy, which has two implications. The first is that it demonstrates clearly that the security of TLS is unchanged, as a server and client can have their entire transcript intercepted by two proxies (one in front of each), which TurboTLS-ify the interaction. Thus the view server and client is unchanged versus standard TLS. The second is that the TLS proxy represents a way for legacy systems to benefit from faster connection establishment without requiring direct upgrades.

- **Performance considerations** Due to the parallelization of the UDP flow and TCP flows, as well as the TCP fallback mechanism, TurboTLS will have some impact on bandwidth requirements. We discuss these briefly, as well as the expected benefit from reducing a round trip when TurboTLS works and the small latency overhead when it doesn't and reverts to TLS-over-TCP. 

It intentionally does not address:

- **Protocol design of TLS:** The internal workings and security mechanisms of TLS are not affected by TurboTLS, as can be seen via the transparent proxying argument. This document does not discuss the design or merits of any version of TLS.


## Goals {#goals}

- **High performance:** Successful use of TurboTLS removes one round trip and should cut handshaking time by up to 50%. However in the worst case, when the fallback mechanism to TLS-over-TCP is used, there should be only a minimal impact on latency.

- **Ease of implementation:** TurboTLS should be designed such that it is possible to implement in many scenarios where other more invasive upgrades may not be possible, such as switching to QUIC. Transparent proxying should enable this via network proxies, sidecar proxies, or directly modifying the client/server applications.

- **Security:** The design should not create any opportunities for adversaries, either to attack TurboTLS servers or to use them e.g. during a reflection attack. The ratio of received:sent UDP packets, in particular, affects an adversary's chances of carrying out such reflection attacks. The handling of semi-open TCP connections is also important to consider in mitigating DoS attacks.



# Transport Layer Security {#TLS}
The Transport Layer Security (TLS) protocol is ubiquitous and provides security services to many network applications.  TLS runs over TCP.  As shown in **DJ ref fig**, the main flow for TLS 1.3 connection establishment {{RFC8446}} in a web browser is as follows. 

First of all, the client makes a DNS query to convert the requested domain name into an IP address.  Simultaneously, browsers request an HTTPS resource record [draft-ietf-dnsop-svcb-https-11](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/11/) from the DNS server which can provide additional information about the server's HTTPS configuration.  Next, the client and server perform the TCP three-way handshake.  Once the TCP handshake is complete and a TCP connection is established, the TLS handshake can start; it requires one round trip -- one client-to-server C->S flow and one server-to-client S->C flow -- before the client can start transmitting application data.  

In total (not including the DNS resolution) this results in two round trips before the client can send the first byte of application data (the TCP handshake, plus the first C->S and S->C flows of the TLS handshake), and one further round trip before the client receives its first byte of response.

TLS does have a pre-shared key mode that allows for an abbreviated handshake permitting application data to be sent in the first C->S TLS flow, but this requires that the client and server have a pre-shared key in advance, established either through some out-of-band mechanism or saved from a previous TLS connection for session resumption. 

# Construction for TurboTLS {#construction}
```
┌──────────┐                        ┌──────────┐    ┌──────────┐                        ┌──────────┐
│TLS client│                        │DNS server│    │TLS client│                        │DNS server│
└──────────┘                        └──────────┘    └──────────┘                        └──────────┘
               DNS: A request                                      DNS: A request
     ────────────────────────────────────►               ────────────────────────────────────►
              DNS: AAAA request                                   DNS: AAAA request
     ────────────────────────────────────►               ────────────────────────────────────►
             DNS: HTTPS RR request                               DNS: HTTPS RR request
     ────────────────────────────────────►               ────────────────────────────────────►
               DNS: A response                                     DNS: A response
     ◄────────────────────────────────────               ◄────────────────────────────────────
              DNS: AAAA response                                  DNS: AAAA response
     ◄────────────────────────────────────               ◄────────────────────────────────────
             DNS: HTTPS RR response                        DNS: HTTPS RR response w/ TTLS flag
     ◄────────────────────────────────────               ◄────────────────────────────────────

┌──────────┐                        ┌──────────┐    ┌──────────┐                        ┌──────────┐
│TLS client│                        │TLS server│    │TLS client│                        │TLS server│
└──────────┘                        └──────────┘    └──────────┘                        └──────────┘
                 TCP: SYN                                  UDP: TurboTLS id, TLS CH frag#1
     ────────────────────────────────────►  │            ────────────────────────────────────►  │
                TCP: SYN-ACK                │RT1           UDP: TurboTLS id, TLS CH frag#1      │
     ◄────────────────────────────────────  │            ────────────────────────────────────►  │
                                                           UDP: TurboTLS id, empty frag#1       │
                 TCP: ACK                                ────────────────────────────────────►  │
     ────────────────────────────────────►  │              UDP: TurboTLS id, empty frag#2       │
                TCP: TLS CH                 │            ────────────────────────────────────►  │
     ────────────────────────────────────►  │                                                   │
                TCP: TLS SH                 │RT2                     TCP: SYN                   │
     ◄────────────────────────────────────  │            ────────────────────────────────────►  │
              TCP: TLS app data             │                                                   │RT1
     ◄────────────────────────────────────  │              UDP: TurboTLS id, TLS resp frag#1    │
                                                         ◄────────────────────────────────────  │
                TCP: TLS *, FIN                            UDP: TurboTLS id, TLS resp frag#2    │
     ────────────────────────────────────►  │            ◄────────────────────────────────────  │
              TCP: TLS app data             │RT3           UDP: TurboTLS id, TLS resp frag#3    │
     ────────────────────────────────────►  │            ◄────────────────────────────────────  │
                                                                                                │
                                                                    TCP: SYN-ACK                │
                                                         ◄────────────────────────────────────  │

                                                                     TCP: ACK
                                                         ────────────────────────────────────►  │
                                                           TCP: TurboTLS id, TLS *, FIN         │
                                                         ────────────────────────────────────►  │RT2
                                                                  TCP: TLS app data             │
                                                         ────────────────────────────────────►  │
```
As described in **ref fig**, TurboTLS sends part of the TLS handshake over UDP, rather than TCP.
Switching from TCP to UDP for handshake establishment means we cannot rely on TCP's features, namely connection-oriented, reliable, in-order delivery.  
However, since the rest of the connection will still run over TCP and only part of the handshake runs over UDP,
we can reproduce the required functionality in a lightweight way without adding latency and allowing for a simple implementation.

## Fragmentation {#Construction-fragmentation}
One of the major problems to deal with is that of fragmentation.  TLS handshake messages can be too large to fit in a single packet -- especially with long certificate chains or if post-quantum algorithms are used.  

Obviously the client can fragment its first C->S flow across multiple UDP packets.  To allow a server to link fragments received across multiple UDP requests, we add a 12-byte connection identifier field, containing a client-selected random value _id_ that is used across all TurboTLS fragments sent by the client. The connection identifier is also included in the first message on the established TLS connection to allow the server to link together data received on the UDP and TCP connections. To allow the server to reassemble fragments if they arrive out-of-order, each fragment includes the total length of the original message as well as the offset of the current fragment; this can allow the server to easily copy fragments into the right position within a buffer as they are received.

Similarly, the server can fragment its first S->C flow across multiple UDP packets.  One additional problem here however is that the S->C flow is typically larger than the C->S flow (as it typically contains one or more certificates), so the server may have to send more UDP response packets than UDP request packets.  As noted by \cite{song-atr-large-resp-03} in the context of DNSSEC, many network devices do not behave well when receiving multiple UDP responses to a single UDP request, and may close the port after the first packet, dropping the request.  Subsequent packets received at a closed port lead to ICMP failure alerts, which can be a nuisance.

### Client request-based fragmentation {#Construction-CRBF}
We employ a recent method proposed by Goertzen and Stebila \cite{arxiv.2211.14196} for DNSSEC: request-based fragmentation.  In the context of large resource records in DNSSEC, \cite{arxiv.2211.14196} had the first response be a truncated response that included information about the size of the response, and then the client sent multiple additional requests, in parallel, for the remaining fragments.  This ensured that there was only one UDP response for each UDP request.  We adapt that method for TurboTLS: the client, in its first C->S flow, fragments its own C->S data across multiple UDP packets, and additionally sends (in parallel) enough nearly-empty UDP requests for a predicted upper bound on the number of fragments the server will need to fit its response.  This preserves the model of each UDP request receiving a single UDP response, reducing the impact of misbehaving network devices and also reducing the potential for DDoS amplification attacks.

## TLS-over-TCP fallback {#Construction-fallback}
UDP does not have reliable delivery, so packets may be lost.  Since the first TurboTLS round-trip includes the TCP handshake, we can immediately fall back to TCP if a UDP packet is lost in either direction.  This will induce a latency cost of however long the client decides to wait for UDP packets to arrive before giving up and assuming they were lost.

In an implementation, the client delay could be a fixed number of milliseconds, or could be variable depending on observed network conditions; this need not be fixed by a standard.
We believe that in many cases a client delay of just 2ms after the TCP reply is received in the first round trip will be enough to ensure UDP responses are received a large majority of the time.  In other words, by tolerating a potential 2ms of extra latency on $X$\% of connections, we can save an entire round-trip on a large proportion ($100-X$\%) of the connections. 
This mechanic was not implemented in the experimental results presented here and constitutes future work.

## TurboTLS support advertisment {#Construction-advertisment}
To protect servers who do not support TurboTLS from being bombarded with unwanted UDP traffic, it would be preferable if clients only used TurboTLS with servers that they already know support it.  Clients could cache this information from previous non-TurboTLS connections, but in fact we can do better.  Even on the first visit to a server, we can communicate server support for TurboTLS to the client, without an extra round trip, using the HTTPS resource record in DNS \cite{ietf-dnsop-svcb-https-11}.  Today when web browsers perform the DNS lookup for the domain name in question, they typically send three requests in parallel: an A query for an IPv4 address, an AAAA query for an IPv6 address, and a query for an HTTPS resource record \cite{ietf-dnsop-svcb-https-11}.  Servers can advertise support for TurboTLS with an additional flag in the HTTPS resource record and clients can check for it without incurring any extra latency.

# Discussion {#discussion}


# Security Considerations {#security-considerations}

## Transparent proxying {#security-proxy}

## Denial-of-Service {#security-DoS}

# Acknowledgements



--- back

# Related work {#related-work}


