---
title: Hybrid key exchange in TLS 1.3
abbrev: ietf-tls-hybrid-design
docname: draft-ietf-tls-hybrid-design-latest
date: 2023-11-09
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

submissionType: IETF

author:
  -
    ins: D. Stebila
    name: Douglas Stebila
    organization: University of Waterloo
    email: dstebila@uwaterloo.ca
  -
    ins: S. Fluhrer
    name: Scott Fluhrer
    organization: Cisco Systems
    email: sfluhrer@cisco.com
  -
    ins: S. Gueron
    name: Shay Gueron
    organization: University of Haifa
    abbrev: U. Haifa
    email: shay.gueron@gmail.com

normative:
  TLS13: RFC8446
  RFC8174: RFC8174

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
  X25519Kyber768: I-D.draft-tls-westerbaan-xyber768d00
  SECP256R1Kyber768: I-D.draft-kwiatkowski-tls-ecdhe-kyber
  KyberDraft00: I-D.draft-cfrg-schwabe-kyber

--- abstract

Hybrid key exchange refers to using multiple key exchange algorithms simultaneously and combining the result with the goal of providing security even if all but one of the component algorithms is broken.  It is motivated by transition to post-quantum cryptography.  This document provides a construction for hybrid key exchange in the Transport Layer Security (TLS) protocol version 1.3.

Discussion of this work is encouraged to happen on the TLS IETF mailing list tls@ietf.org or on the GitHub repository which contains the draft: https://github.com/dstebila/draft-ietf-tls-hybrid-design.

--- middle

# Introduction {#introduction}

This document gives a construction for hybrid key exchange in TLS 1.3.  The overall design approach is a simple, "concatenation"-based approach: each hybrid key exchange combination should be viewed as a single new key exchange method, negotiated and transmitted using the existing TLS 1.3 mechanisms.

This document does not propose specific post-quantum mechanisms; see {{scope}} for more on the scope of this document.

## Revision history

> **RFC Editor's Note:** Please remove this section prior to publication of a final version of this document.

Earlier versions of this document categorized various design decisions one could make when implementing hybrid key exchange in TLS 1.3.

- draft-ietf-tls-hybrid-design-09:
    - Remove IANA registry requests
    - Editorial changes
- draft-ietf-tls-hybrid-design-09:
    - Removal of TBD hybrid combinations using Kyber512 or secp384r1
    - Editorial changes
- draft-ietf-tls-hybrid-design-08:
    - Add reference to {{SECP256R1Kyber768}} and {{KyberDraft00}} drafts
- draft-ietf-tls-hybrid-design-07:
    - Editorial changes
    - Add reference to {{X25519Kyber768}} draft
- draft-ietf-tls-hybrid-design-06:
    - Bump to version -06 to avoid expiry
- draft-ietf-tls-hybrid-design-05:
    - Define four hybrid key exchange methods
    - Updates to reflect NIST's selection of Kyber
    - Clarifications and rewordings based on working group comments
- draft-ietf-tls-hybrid-design-04:
    - Some wording changes
    - Remove design considerations appendix
- draft-ietf-tls-hybrid-design-03:
    - Remove specific code point examples and requested codepoint range for hybrid private use
    - Change "Open questions" to "Discussion"
    - Some wording changes
- draft-ietf-tls-hybrid-design-02:
    - Bump to version -02 to avoid expiry
- draft-ietf-tls-hybrid-design-01:
    - Forbid variable-length secret keys
    - Use fixed-length KEM public keys/ciphertexts
- draft-ietf-tls-hybrid-design-00:
    - Allow key_exchange values from the same algorithm to be reused across multiple KeyShareEntry records in the same ClientHello.
- draft-stebila-tls-hybrid-design-03:
    - Add requirement for KEMs to provide protection against key reuse.
    - Clarify FIPS-compliance of shared secret concatenation method.
- draft-stebila-tls-hybrid-design-02:
    - Design considerations from draft-stebila-tls-hybrid-design-00 and draft-stebila-tls-hybrid-design-01 are moved to the appendix.
    - A single construction is given in the main body.
- draft-stebila-tls-hybrid-design-01:
    - Add (Comb-KDF-1) and (Comb-KDF-2) options.
    - Add two candidate instantiations.
- draft-stebila-tls-hybrid-design-00: Initial version.

## Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
capitals, as shown here.

For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

- "Traditional" algorithms: Algorithms which are widely deployed today, but which may be deprecated in the future.  In the context of TLS 1.3, examples of traditional key exchange algorithms include elliptic curve Diffie-Hellman using secp256r1 or x25519, or finite-field Diffie-Hellman.
- "Next-generation" (or "next-gen") algorithms: Algorithms which are not yet widely deployed, but which may eventually be widely deployed.  An additional facet of these algorithms may be that we have less confidence in their security due to them being relatively new or less studied.  This includes "post-quantum" algorithms.

"Hybrid" key exchange, in this context, means the use of two (or more) key exchange algorithms based on different cryptographic assumptions, e.g., one traditional algorithm and one next-gen algorithm, with the purpose of the final session key being secure as long as at least one of the component key exchange algorithms remains unbroken.
When one of the algorithms is traditional and one of them is post-quantum, this is a Post-Quantum Traditional Hybrid Scheme {{?I-D.driscoll-pqt-hybrid-terminology}}; while this is the initial use case for this draft, we do not limit this draft to that case.
We use the term "component" algorithms to refer to the algorithms combined in a hybrid key exchange.

We note that some authors prefer the phrase "composite" to refer to the use of multiple algorithms, to distinguish from "hybrid public key encryption" in which a key encapsulation mechanism and data encapsulation mechanism are combined to create public key encryption.

It is intended that the composite algorithms within a hybrid key exchange are to be performed, that is, negotiated and transmitted, within the TLS 1.3 handshake.  Any out-of-band method of exchanging keying material is considered out-of-scope.

The primary motivation of this document is preparing for post-quantum algorithms.  However, it is possible that public key cryptography based on alternative mathematical constructions will be desired to mitigate risks independent of the advent of a quantum computer, for example because of a cryptanalytic breakthrough.  As such we opt for the more generic term "next-generation" algorithms rather than exclusively "post-quantum" algorithms.

Note that TLS 1.3 uses the phrase "groups" to refer to key exchange algorithms -- for example, the `supported_groups` extension -- since all key exchange algorithms in TLS 1.3 are Diffie-Hellman-based.  As a result, some parts of this document will refer to data structures or messages with the term "group" in them despite using a key exchange algorithm that is not Diffie-Hellman-based nor a group.

## Motivation for use of hybrid key exchange {#motivation}

A hybrid key exchange algorithm allows early adopters eager for post-quantum security to have the potential of post-quantum security (possibly from a less-well-studied algorithm) while still retaining at least the security currently offered by traditional algorithms.  They may even need to retain traditional algorithms due to regulatory constraints, for example FIPS compliance.

Ideally, one would not use hybrid key exchange: one would have confidence in a single algorithm and parameterization that will stand the test of time.  However, this may not be the case in the face of quantum computers and cryptanalytic advances more generally.

Many (though not all) post-quantum algorithms currently under consideration are relatively new; they have not been subject to the same depth of study as RSA and finite-field or elliptic curve Diffie-Hellman, and thus the security community does not necessarily have as much confidence in their fundamental security, or the concrete security level of specific parameterizations.

Moreover, it is possible that after next-generation algorithms are defined, and for a period of time thereafter, conservative users may not have full confidence in some algorithms.

Some users may want to accelerate adoption of post-quantum cryptography due to the threat of retroactive decryption: if a cryptographic assumption is broken due to the advent of a quantum computer or some other cryptanalytic breakthrough, confidentiality of information can be broken retroactively by any adversary who has passively recorded handshakes and encrypted communications.  Hybrid key exchange enables potential security against retroactive decryption while not fully abandoning traditional cryptosystems.

As such, there may be users for whom hybrid key exchange is an appropriate step prior to an eventual transition to next-generation algorithms. Users should consider the confidence they have in each hybrid component to assess that the hybrid system meets the desired motivation.

## Scope {#scope}

This document focuses on hybrid ephemeral key exchange in TLS 1.3 {{TLS13}}.  It intentionally does not address:

- Selecting which next-generation algorithms to use in TLS 1.3, or algorithm identifiers or encoding mechanisms for next-generation algorithms.  This selection will be based on the recommendations by the Crypto Forum Research Group (CFRG), which is currently waiting for the results of the NIST Post-Quantum Cryptography Standardization Project {{NIST}}.
- Authentication using next-generation algorithms.  While quantum computers could retroactively decrypt previous sessions, session authentication cannot be retroactively broken.

## Goals {#goals}

The primary goal of a hybrid key exchange mechanism is to facilitate the establishment of a shared secret which remains secure as long as as one of the component key exchange mechanisms remains unbroken.

In addition to the primary cryptographic goal, there may be several additional goals in the context of TLS 1.3:

- **Backwards compatibility:** Clients and servers who are "hybrid-aware", i.e., compliant with whatever hybrid key exchange standard is developed for TLS, should remain compatible with endpoints and middle-boxes that are not hybrid-aware.  The three scenarios to consider are:
    1. Hybrid-aware client, hybrid-aware server: These parties should establish a hybrid shared secret.
    2. Hybrid-aware client, non-hybrid-aware server:  These parties should establish a traditional shared secret (assuming the hybrid-aware client is willing to downgrade to traditional-only).
    3. Non-hybrid-aware client, hybrid-aware server:  These parties should establish a traditional shared secret (assuming the hybrid-aware server is willing to downgrade to traditional-only).

    Ideally backwards compatibility should be achieved without extra round trips and without sending duplicate information; see below.

- **High performance:** Use of hybrid key exchange should not be prohibitively expensive in terms of computational performance.  In general this will depend on the performance characteristics of the specific cryptographic algorithms used, and as such is outside the scope of this document.  See {{PST}} for preliminary results about performance characteristics.

- **Low latency:** Use of hybrid key exchange should not substantially increase the latency experienced to establish a connection.  Factors affecting this may include the following.
    - The computational performance characteristics of the specific algorithms used.  See above.
    - The size of messages to be transmitted.  Public key and ciphertext sizes for post-quantum algorithms range from hundreds of bytes to over one hundred kilobytes, so this impact can be substantial.  See {{PST}} for preliminary results in a laboratory setting, and {{LANGLEY}} for preliminary results on more realistic networks.
    - Additional round trips added to the protocol.  See below.

- **No extra round trips:** Attempting to negotiate hybrid key exchange should not lead to extra round trips in any of the three hybrid-aware/non-hybrid-aware scenarios listed above.

- **Minimal duplicate information:** Attempting to negotiate hybrid key exchange should not mean having to send multiple public keys of the same type.

# Key encapsulation mechanisms {#kems}

This document models key agreement as key encapsulation mechanisms (KEMs), which consist of three algorithms:

- `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm, which generates a public key `pk` and a secret key `sk`.
- `Encaps(pk) -> (ct, ss)`: A probabilistic encapsulation algorithm, which takes as input a public key `pk` and outputs a ciphertext `ct` and shared secret `ss`.
- `Decaps(sk, ct) -> ss`: A decapsulation algorithm, which takes as input a secret key `sk` and ciphertext `ct` and outputs a shared secret `ss`, or in some cases a distinguished error value.

The main security property for KEMs is indistinguishability under adaptive chosen ciphertext attack (IND-CCA2), which means that shared secret values should be indistinguishable from random strings even given the ability to have other arbitrary ciphertexts decapsulated.  IND-CCA2 corresponds to security against an active attacker, and the public key / secret key pair can be treated as a long-term key or reused.  A common design pattern for obtaining security under key reuse is to apply the Fujisaki-Okamoto (FO) transform {{FO}} or a variant thereof {{HHK}}.

A weaker security notion is indistinguishability under chosen plaintext attack (IND-CPA), which means that the shared secret values should be indistinguishable from random strings given a copy of the public key.  IND-CPA roughly corresponds to security against a passive attacker, and sometimes corresponds to one-time key exchange.

Key exchange in TLS 1.3 is phrased in terms of Diffie-Hellman key exchange in a group.  DH key exchange can be modeled as a KEM, with `KeyGen` corresponding to selecting an exponent `x` as the secret key and computing the public key `g^x`; encapsulation corresponding to selecting an exponent `y`, computing the ciphertext `g^y` and the shared secret `g^(xy)`, and decapsulation as computing the shared secret `g^(xy)`. See {{HPKE}} for more details of such Diffie-Hellman-based key encapsulation mechanisms. Diffie-Hellman key exchange, when viewed as a KEM, does not formally satisfy IND-CCA2 security, but is still safe to use for ephemeral key exchange in TLS 1.3, see e.g. {{DOWLING}}.

TLS 1.3 does not require that ephemeral public keys be used only in a single key exchange session; some implementations may reuse them, at the cost of limited forward secrecy.  As a result, any KEM used in the manner described in this document MUST explicitly be designed to be secure in the event that the public key is reused.  Finite-field and elliptic-curve Diffie-Hellman key exchange methods used in TLS 1.3 satisfy this criteria.  For generic KEMs, this means satisfying IND-CCA2 security or having a transform like the Fujisaki-Okamoto transform {{FO}} {{HHK}} applied.  While it is recommended that implementations avoid reuse of KEM public keys, implementations that do reuse KEM public keys MUST ensure that the number of reuses of a KEM public key abides by any bounds in the specification of the KEM or subsequent security analyses.  Implementations MUST NOT reuse randomness in the generation of KEM ciphertexts.

# Construction for hybrid key exchange {#construction}

## Negotiation {#construction-negotiation}

Each particular combination of algorithms in a hybrid key exchange will be represented as a `NamedGroup` and sent in the `supported_groups` extension.  No internal structure or grammar is implied or required in the value of the identifier; they are simply opaque identifiers.

Each value representing a hybrid key exchange will correspond to an ordered pair of two or more algorithms.  (We note that this is independent from future documents standardizing solely post-quantum key exchange methods, which would have to be assigned their own identifier.)

Specific values shall be registered by IANA in the TLS Supported Groups registry.

~~~
    enum {

          /* Elliptic Curve Groups (ECDHE) */
          secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
          x25519(0x001D), x448(0x001E),

          /* Finite Field Groups (DHE) */
          ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
          ffdhe6144(0x0103), ffdhe8192(0x0104),

          /* Hybrid Key Exchange Methods */
          ...,

          /* Reserved Code Points */
          ffdhe_private_use(0x01FC..0x01FF),
          ecdhe_private_use(0xFE00..0xFEFF),
          (0xFFFF)
    } NamedGroup;
~~~

## Transmitting public keys and ciphertexts {#construction-transmitting}

We take the relatively simple "concatenation approach": the messages from the two or more algorithms being hybridized will be concatenated together and transmitted as a single value, to avoid having to change existing data structures.  The values are directly concatenated, without any additional encoding or length fields; the representation and length of elements MUST be fixed once the algorithm is fixed.

Recall that in TLS 1.3 a KEM public key or KEM ciphertext is represented as a `KeyShareEntry`:

~~~
    struct {
        NamedGroup group;
        opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;
~~~

These are transmitted in the `extension_data` fields of `KeyShareClientHello` and `KeyShareServerHello` extensions:

~~~
    struct {
        KeyShareEntry client_shares<0..2^16-1>;
    } KeyShareClientHello;

    struct {
        KeyShareEntry server_share;
    } KeyShareServerHello;
~~~

The client's shares are listed in descending order of client preference; the server selects one algorithm and sends its corresponding share.

For a hybrid key exchange, the `key_exchange` field of a `KeyShareEntry` is the concatenation of the `key_exchange` field for each of the constituent algorithms.  The order of shares in the concatenation MUST be the same as the order of algorithms indicated in the definition of the `NamedGroup`.

For the client's share, the `key_exchange` value contains the concatenation of the `pk` outputs of the corresponding KEMs' `KeyGen` algorithms, if that algorithm corresponds to a KEM; or the (EC)DH ephemeral key share, if that algorithm corresponds to an (EC)DH group.  For the server's share, the `key_exchange` value contains concatenation of the `ct` outputs of the corresponding KEMs' `Encaps` algorithms, if that algorithm corresponds to a KEM; or the (EC)DH ephemeral key share, if that algorithm corresponds to an (EC)DH group.

{{TLS13}} requires that ``The key_exchange values for each KeyShareEntry MUST be generated independently.''  In the context of this document, since the same algorithm may appear in multiple named groups, we relax the above requirement to allow the same key_exchange value for the same algorithm to be reused in multiple KeyShareEntry records sent in within the same `ClientHello`.  However, key_exchange values for different algorithms MUST be generated independently.

## Shared secret calculation {#construction-shared-secret}

Here we also take a simple "concatenation approach": the two shared secrets are concatenated together and used as the shared secret in the existing TLS 1.3 key schedule.  Again, we do not add any additional structure (length fields) in the concatenation procedure: for both the traditional groups and Kyber, the shared secret output length is fixed for a specific elliptic curve or parameter set.

In other words, if the `NamedGroup` is `MyECDHMyPQKEM`, the shared secret is calculated as

~~~
concatenated_shared_secret = MyECDH.shared_secret || MyPQKEM.shared_secret
~~~

and inserted into the TLS 1.3 key schedule in place of the (EC)DHE shared secret, as shown in {{fig-key-schedule}}.

~~~~
                                    0
                                    |
                                    v
                      PSK ->  HKDF-Extract = Early Secret
                                    |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    |
                                    v
                              Derive-Secret(., "derived", "")
                                    |
                                    v
concatenated_shared_secret -> HKDF-Extract = Handshake Secret
^^^^^^^^^^^^^^^^^^^^^^^^^^          |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    |
                                    v
                              Derive-Secret(., "derived", "")
                                    |
                                    v
                         0 -> HKDF-Extract = Master Secret
                                    |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
~~~~
{: #fig-key-schedule title="Key schedule for hybrid key exchange"}

**FIPS-compliance of shared secret concatenation.**
{{NIST-SP-800-56C}} or {{NIST-SP-800-135}} give NIST recommendations for key derivation methods in key exchange protocols.  Some hybrid combinations may combine the shared secret from a NIST-approved algorithm (e.g., ECDH using the nistp256/secp256r1 curve) with a shared secret from a non-approved algorithm (e.g., post-quantum).  {{NIST-SP-800-56C}} lists simple concatenation as an approved method for generation of a hybrid shared secret in which one of the constituent shared secret is from an approved method.

# Discussion {#discussion}

**Larger public keys and/or ciphertexts.**
The `HybridKeyExchange` struct in {{construction-transmitting}} limits public keys and ciphertexts to 2^16-1 bytes; this is bounded by the same (2^16-1)-byte limit on the `key_exchange` field in the `KeyShareEntry` struct.  Some post-quantum KEMs have larger public keys and/or ciphertexts; for example, Classic McEliece's smallest parameter set has public key size 261,120 bytes.  However, all defined parameter sets for Kyber have public keys and ciphertexts that fall within the TLS constraints.

**Duplication of key shares.**
Concatenation of public keys in the `HybridKeyExchange` struct as described in {{construction-transmitting}} can result in sending duplicate key shares.  For example, if a client wanted to offer support for two combinations, say "SecP256r1Kyber768Draft00" and "X25519Kyber768Draft00", it would end up sending two kyber768 public keys, since the `KeyShareEntry` for each combination contains its own copy of a kyber768 key.  This duplication may be more problematic for post-quantum algorithms which have larger public keys.  On the other hand, if the client wants to offer, for example "SecP256r1Kyber768Draft00" and "secp256r1" (for backwards compatibility), there is relatively little duplicated data (as the secp256r1 keys are comparatively small).

**Failures.**
Some post-quantum key exchange algorithms, including Kyber, have non-zero probability of failure, meaning two honest parties may derive different shared secrets.  This would cause a handshake failure.  Kyber has a cryptographically small failure rate; if other algorithms are used, implementers should be aware of the potential of handshake failure. Clients can retry if a failure is encountered.

# IANA Considerations

IANA will assign identifiers from the TLS Supported Groups section for the hybrid combinations defined following this document.
These assignments should be made in a range that is distinct from the Elliptic Curve Groups and the Finite Field Groups ranges.

# Security Considerations {#security-considerations}

The shared secrets computed in the hybrid key exchange should be computed in a way that achieves the "hybrid" property: the resulting secret is secure as long as at least one of the component key exchange algorithms is unbroken.  See {{GIACON}} and {{BINDEL}} for an investigation of these issues.  Under the assumption that shared secrets are fixed length once the combination is fixed, the construction from {{construction-shared-secret}} corresponds to the dual-PRF combiner of {{BINDEL}} which is shown to preserve security under the assumption that the hash function is a dual-PRF.

As noted in {{kems}}, KEMs used in the manner described in this document MUST explicitly be designed to be secure in the event that the public key is reused, such as achieving IND-CCA2 security or having a transform like the Fujisaki-Okamoto transform applied.  Kyber has such security properties.  However, some other post-quantum KEMs are designed to be IND-CPA-secure (i.e., without countermeasures such as the FO transform) are completely insecure under public key reuse; for example, some lattice-based IND-CPA-secure KEMs are vulnerable to attacks that recover the private key after just a few thousand samples {{FLUHRER}}.

**Public keys, ciphertexts, and secrets should be constant length.**
This document assumes that the length of each public key, ciphertext, and shared secret is fixed once the algorithm is fixed.  This is the case for Kyber.

Note that variable-length secrets are, generally speaking, dangerous.  In particular, when using key material of variable length and processing it using hash functions, a timing side channel may arise.  In broad terms, when the secret is longer, the hash function may need to process more blocks internally.  In some unfortunate circumstances, this has led to timing attacks, e.g. the Lucky Thirteen {{LUCKY13}} and Raccoon {{RACCOON}} attacks.

Furthermore, {{AVIRAM}} identified a risk of using variable-length secrets when the hash function used in the key derivation function is no longer collision-resistant.

If concatenation were to be used with values that are not fixed-length, a length prefix or other unambiguous encoding would need to be used to ensure that the composition of the two values is injective and requires a mechanism different from that specified in this document.

Therefore, this specification MUST only be used with algorithms which have fixed-length shared secrets (after the variant has been fixed by the algorithm identifier in the `NamedGroup` negotiation in {{construction-negotiation}}).

# Acknowledgements

These ideas have grown from discussions with many colleagues, including Christopher Wood, Matt Campagna, Eric Crockett, authors of the various hybrid Internet-Drafts and implementations cited in this document, and members of the TLS working group.  The immediate impetus for this document came from discussions with attendees at the Workshop on Post-Quantum Software in Mountain View, California, in January 2019.  Daniel J. Bernstein and Tanja Lange commented on the risks of reuse of ephemeral public keys.  Matt Campagna and the team at Amazon Web Services provided additional suggestions.  Nimrod Aviram proposed restricting to fixed-length secrets.

--- back

# Related work {#related-work}

Quantum computing and post-quantum cryptography in general are outside the scope of this document.  For a general introduction to quantum computing, see a standard textbook such as {{NIELSEN}}.  For an overview of post-quantum cryptography as of 2009, see {{BERNSTEIN}}.  For the current status of the NIST Post-Quantum Cryptography Standardization Project, see {{NIST}}.  For additional perspectives on the general transition from traditional to post-quantum cryptography, see for example {{ETSI}}, among others.

There have been several Internet-Drafts describing mechanisms for embedding post-quantum and/or hybrid key exchange in TLS:

- Internet-Drafts for TLS 1.2: {{WHYTE12}}, {{CAMPAGNA}}
- Internet-Drafts for TLS 1.3: {{KIEFER}}, {{SCHANCK}}, {{WHYTE13}}

There have been several prototype implementations for post-quantum and/or hybrid key exchange in TLS:

- Experimental implementations in TLS 1.2: {{BCNS15}}, {{CECPQ1}}, {{FRODO}}, {{OQS-102}}, {{S2N}}
- Experimental implementations in TLS 1.3: {{CECPQ2}}, {{OQS-111}}, {{OQS-PROV}}, {{PST}}

These experimental implementations have taken an ad hoc approach and not attempted to implement one of the drafts listed above.

Unrelated to post-quantum but still related to the issue of combining multiple types of keying material in TLS is the use of pre-shared keys, especially the recent TLS working group document on including an external pre-shared key {{EXTERN-PSK}}.

Considering other IETF standards, there is work on post-quantum preshared keys in IKEv2 {{IKE-PSK}} and a framework for hybrid key exchange in IKEv2 {{IKE-HYBRID}}.  The XMSS hash-based signature scheme has been published as an informational RFC by the IRTF {{XMSS}}.

In the academic literature, {{EVEN}} initiated the study of combining multiple symmetric encryption schemes; {{ZHANG}}, {{DODIS}}, and {{HARNIK}} examined combining multiple public key encryption schemes, and {{HARNIK}} coined the term "robust combiner" to refer to a compiler that constructs a hybrid scheme from individual schemes while preserving security properties.  {{GIACON}} and {{BINDEL}} examined combining multiple key encapsulation mechanisms.
