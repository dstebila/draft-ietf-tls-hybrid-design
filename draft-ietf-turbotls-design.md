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
connection-based protocol
connectionless protocol


## Motivation for handshaking over UDP {#motivation}
TLS is the most ubiquitous application layer security protocol in use at the time of writing. Other protocols for secure connection establishment have been proposed, and one such widely-used protocol is QUIC. QUIC runs entirely over UDP and merges the transport and security aspects into one specification, handling packet loss, reordering, handshake establishment, and session management all in one protocol. One benefit of QUIC is that it enjoys fast connection establishment because it runs over UDP, whereas running on TCP would mean waiting for a TCP handshake to occur which requires one round trip.

Many will make the choice to move from TLS to QUIC, however some will not for a range of reasons. Deep packet inspection is inhibited in QUIC, and updating some legacy systems can be difficult. TurboTLS aims to provide a method for those who do not want to fully switch to QUIC, to benefit from the fast connection establishment enabled by UDP, but without fundamentally changing the security properties of TLS, and furthermore enabling implementation via transparent proxying, thus avoiding the need to directly upgrade such systems themselves.



## Scope {#scope}

This document focuses on TurboTLS {{TurboTLS}}. It covers everything needed to achieve the handshaking portion of a TLS connection over UDP, including

- **Construction in principle:** It provides an outline of which flows are sent over UDP, which are sent over TCP and in what order.
- 
- **TLS-over-TCP fallback:** The document describes what to do in the case of failure due to UDP packet loss or filtering. The scheme should revert to TLS-over-TCP incurring a small latency overhead that should be minimal in comparison with standard TLS-over-TCP without a TurboTLS attempt.
- 
- **Client request-based fragmentation:** Due to the impact of post-quantum cryptography such as larger keys certain considerations have to be taken into account. One is that a Server Hello is likely to require multiple UDP packets, thus to eliminate the possibility of reflection attacks and failures due to middle-box filtering, we describe how to create a one-to-one correspondence between Client Hello packets and Server Hello packets.
  
- **How to implement via a transparent proxy:** The document gives a brief description of how one can implement TurboTLS via a transparent proxy, which has two implications. The first is that it demonstrates clearly that the security of TLS is unchanged, as a server and client can have their entire transcript intercepted by two proxies (one in front of each), which TurboTLS-ify the interaction. Thus the view server and client is unchanged versus standard TLS. The second is that the TLS proxy represents a way for legacy systems to benefit from faster connection establishment without requiring direct upgrades.

- **Performance considerations** Due to the parallelization of the UDP flow and TCP flows, as well as the TCP fallback mechanism, TurboTLS will have some impact on bandwidth requirements. We discuss these briefly, as well as the expected benefit from reducing a round trip when TurboTLS works and the small latency overhead when it doesn't and reverts to TLS-over-TCP. 

It intentionally does not address:

- **Protocol design of TLS:** The internal workings and security mechanisms of TLS are not affected by TurboTLS, as can be seen via the transparent proxying argument. This document does not discuss the design or merits of any version of TLS.


## Goals {#goals}

- **High performance:** Use of hybrid key exchange should not be prohibitively expensive in terms of computational performance.  In general this will depend on the performance characteristics of the specific cryptographic algorithms used, and as such is outside the scope of this document.  See {{PST}} for preliminary results about performance characteristics.

- **Low latency:** Use of hybrid key exchange should not substantially increase the latency experienced to establish a connection.  Factors affecting this may include the following.
    - The computational performance characteristics of the specific algorithms used.  See above.
    - The size of messages to be transmitted.  Public key and ciphertext sizes for post-quantum algorithms range from hundreds of bytes to over one hundred kilobytes, so this impact can be substantial.  See {{PST}} for preliminary results in a laboratory setting, and {{LANGLEY}} for preliminary results on more realistic networks.
    - Additional round trips added to the protocol.  See below.

- **No extra round trips:** Attempting to negotiate hybrid key exchange should not lead to extra round trips in any of the three hybrid-aware/non-hybrid-aware scenarios listed above.



# Transport Layer Security {#TLS}


# Construction for TurboTLS {#construction}

## Client request-based fragmentation {#CRBF}

## TLS-over-TCP fallback {#construction-fallback}


# Discussion {#discussion}


# Security Considerations {#security-considerations}

# Transparent proxying {#security-proxy}

# Acknowledgements



--- back

# Related work {#related-work}

