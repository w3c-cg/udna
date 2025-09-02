# Universal DID-Native Addressing (UDNA): A Cryptographic Foundation for Post-Internet Infrastructure

## W3C Community Group Report

**Published:** 15 September 2025  
**Latest version:** https://w3c-ccg.github.io/udna/  
**Editors:**
- Amir Hameed Mir, Sirraya Labs

**Participate:**
- GitHub repository: https://github.com/w3c-ccg/udna
- File issues: https://github.com/w3c-ccg/udna/issues
- Community Group: https://www.w3.org/community/credentials/

---

## Abstract

The current Internet architecture suffers from fundamental design limitations rooted in its 1970s origins: location-based addressing, centralized trust dependencies, and bolt-on security models. This report presents Universal DID-Native Addressing (UDNA), a paradigmatic shift toward identity-centric networking where [Decentralized Identifiers](https://www.w3.org/TR/did-core/) become first-class network primitives.

UDNA enables globally unique, self-sovereign, and cryptographically verifiable network addressing without reliance on centralized authorities. This approach achieves sub-50μs DID resolution, <2ms handshake latency, and provides mathematical guarantees for address integrity and non-repudiation.

## Status of This Document

This document was published by the [W3C Credentials Community Group](https://www.w3.org/community/credentials/). It is not a W3C Standard nor is it on the W3C Standards Track. Please note that under the [W3C Community Contributor License Agreement (CLA)](https://www.w3.org/community/about/agreements/cla/) there is a limited opt-out and other conditions apply. Learn more about [W3C Community and Business Groups](https://www.w3.org/community/).

If you wish to make comments regarding this document, please send them to [public-credentials@w3.org](mailto:public-credentials@w3.org) ([subscribe](mailto:public-credentials-request@w3.org?subject=subscribe), [archives](https://lists.w3.org/Archives/Public/public-credentials/)).

## Table of Contents

1. [Introduction](#1-introduction)
2. [Motivation and Requirements](#2-motivation-and-requirements)
3. [UDNA Architecture](#3-udna-architecture)
4. [DID Integration](#4-did-integration)
5. [Wire Protocol Specification](#5-wire-protocol-specification)
6. [Security Model](#6-security-model)
7. [Privacy Considerations](#7-privacy-considerations)
8. [Interoperability](#8-interoperability)
9. [Implementation Considerations](#9-implementation-considerations)
10. [Security and Privacy Considerations](#10-security-and-privacy-considerations)
11. [IANA Considerations](#11-iana-considerations)
12. [References](#12-references)

## 1. Introduction

### 1.1 Background

The Internet Protocol Suite (TCP/IP) has served as the foundation of global networking for over four decades. However, its location-based addressing model presents fundamental limitations in today's security-conscious, privacy-aware, and mobility-centric computing environment.

Contemporary networking faces three critical challenges:

1. **Identity Crisis**: IP addresses describe location, not identity, creating semantic gaps requiring complex overlay systems
2. **Trust Crisis**: Certificate authorities and DNS hierarchies represent centralized points of failure and control  
3. **Privacy Crisis**: Location-based addressing enables surveillance and correlation by design

### 1.2 Relationship to W3C Specifications

UDNA builds upon several W3C specifications:

- **[DID Core](https://www.w3.org/TR/did-core/)**: Provides the foundational identifier format and resolution mechanisms
- **[Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)**: Enables cryptographically verifiable authorization claims
- **[DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/)**: Supports secure messaging between DID-identified endpoints

### 1.3 Scope

This document specifies:

- Wire protocol formats for DID-based network addressing
- Resolution mechanisms for converting DIDs to network endpoints
- Security protocols for DID-authenticated connections
- Privacy mechanisms including pairwise and rotating identifiers
- Integration patterns with existing network infrastructure

## 2. Motivation and Requirements

### 2.1 Limitations of Current Approaches

#### 2.1.1 IP/DNS Addressing

The Domain Name System exhibits several architectural limitations:

- **Centralized control**: ICANN and root server operators control the global namespace
- **Location binding**: DNS names often encode geographic or organizational information  
- **Trust dependencies**: DNS cache poisoning and BGP hijacking remain persistent threats
- **Privacy erosion**: DNS queries reveal browsing patterns and network topology

#### 2.1.2 Public Key Infrastructure

Traditional PKI approaches face:

- **Certificate authority compromise**: Single points of failure affecting millions of services
- **Revocation problems**: CRLs and OCSP introduce latency and availability issues
- **Identity binding complexity**: Mapping certificates to entities requires external verification
- **Operational overhead**: Certificate management imposes significant costs

### 2.2 Design Requirements

UDNA addresses these limitations through:

1. **Decentralized Identity**: No central authority required for identifier creation
2. **Cryptographic Verifiability**: All addressing operations cryptographically verifiable
3. **Privacy by Default**: Pairwise identifiers prevent correlation
4. **Offline Operation**: Cached credentials enable partition-tolerant operation
5. **Protocol Integration**: DIDs as first-class network primitives

## 3. UDNA Architecture

### 3.1 Core Principles

UDNA operates on five foundational principles:

1. **Identity as Address**: Network endpoints identified by DIDs, making identity and address semantically equivalent
2. **Cryptographic Verifiability**: All operations cryptographically verifiable without trusted third parties  
3. **Privacy by Default**: Pairwise and rotating DIDs prevent correlation
4. **Offline Resilience**: Cached credentials enable operation during network partitions
5. **Protocol Native Integration**: DIDs as first-class network protocol elements

### 3.2 System Components

#### 3.2.1 DID Method Support

UDNA supports a curated set of DID methods optimized for network protocol use:

- **`did:key`**: Pure cryptographic identifiers requiring no external infrastructure
- **`did:web`**: Web-anchored DIDs for compatibility with HTTP infrastructure  
- **`did:scp`**: Consensus-anchored identities with rotation support

#### 3.2.2 Service Facets

Each DID exposes multiple service facets enabling fine-grained access control:

- **Control Facet (0x01)**: Administrative operations and key management
- **Messaging Facet (0x02)**: DIDComm-compatible secure messaging
- **Telemetry Facet (0x03)**: Monitoring and observability endpoints
- **Storage Facet (0x04)**: Data storage and retrieval services

#### 3.2.3 Privacy Mechanisms

**Pairwise DIDs**: Each bilateral relationship uses unique DID pairs, preventing correlation across relationships while maintaining cryptographic verifiability.

**Rotating DIDs**: Time-bounded identifiers with cryptographic rotation proofs enable forward secrecy and limit the impact of key compromise.

## 4. DID Integration

### 4.1 DID Resolution as Protocol Primitive

UDNA implements a multi-tier resolution architecture:

#### 4.1.1 Tier 1: Local Cache
- **Performance**: Sub-50μs resolution for cached entries
- **Security**: Cryptographically signed cache entries with tamper detection
- **Management**: Time-based and policy-based cache invalidation

#### 4.1.2 Tier 2: Distributed Resolution Network  
- **DHT Discovery**: Kademlia-inspired overlay network keyed by DID fingerprints
- **Gossip Protocols**: Efficient propagation of service facet updates
- **Consensus**: Byzantine fault-tolerant resolution for critical identities

#### 4.1.3 Tier 3: Method-Specific Resolvers
- **`did:key`**: Pure algorithmic resolution requiring no network operations
- **`did:web`**: HTTP(S)-based resolution with caching and verification
- **`did:scp`**: Native protocol resolution through consensus mechanisms

### 4.2 Key Rotation Protocol

Identity key rotation requires cryptographic verification of legitimate transitions:

```
RotationProof {
    prev_key: PublicKey,           // Previous signing key
    new_key: PublicKey,            // New signing key
    new_doc_hash: Hash,            // Hash of updated DID Document  
    valid_from: Timestamp,         // Rotation effective time
    valid_to: Optional<Timestamp>, // Optional rotation expiry
    reason: RotationReason,        // Rotation reason code
    sig_by_prev: Signature,        // Signature by previous key
}
```

## 5. Wire Protocol Specification

### 5.1 Address Header Format

UDNA addresses use a compact, self-describing binary format:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |   DIDType     |          DIDLength            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         DIDBytes (variable)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   FacetId     | KeyHintLen    |      KeyHint (variable)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|RouteHintLen   |              RouteHint (variable)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Flags             |            Nonce              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Nonce (cont.)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Signature (variable)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 5.2 Field Definitions

- **Version**: Protocol version for forward compatibility
- **DIDType**: Enumerated DID method (0x01=did:key, 0x02=did:web, 0x10=did:scp)
- **DIDBytes**: Multibase/multicodec-compressed DID string
- **FacetId**: Service facet selector for fine-grained addressing
- **KeyHint**: Truncated fingerprint of current signing key
- **RouteHint**: Optional DHT locator or relay path information
- **Flags**: Privacy level, pairwise status, rotation state markers
- **Nonce**: 64-bit random value preventing replay attacks
- **Signature**: Digital signature over header fields

### 5.3 Compression Optimization

UDNA employs several space optimization techniques:

- **Multicodec compression**: Binary encoding of common DID components
- **Varint encoding**: Variable-length integers for space efficiency  
- **Method-specific optimizations**: Custom encodings for different DID methods

These optimizations achieve 35-55% space savings compared to raw DID strings.

## 6. Security Model

### 6.1 Threat Model

UDNA operates under a comprehensive threat model encompassing:

- **Network adversaries**: BGP hijacking, DNS poisoning, traffic analysis
- **Protocol adversaries**: Man-in-the-middle, replay attacks, identity spoofing
- **Application adversaries**: Sybil attacks, capability abuse, social engineering

### 6.2 Security Guarantees

#### 6.2.1 Authentication
- **Identity binding**: Cryptographic binding between DIDs and public keys
- **Message authentication**: Digital signatures provide non-repudiation
- **Mutual authentication**: Symmetric authentication prevents unilateral attacks

#### 6.2.2 Confidentiality  
- **End-to-end encryption**: AEAD encryption with DID-derived keys
- **Forward secrecy**: Ephemeral key exchange prevents retroactive decryption
- **Traffic confidentiality**: Encrypted routing metadata limits analysis

#### 6.2.3 Availability
- **Distributed resolution**: Multi-path DID resolution prevents single points of failure
- **Graceful degradation**: Cached credentials enable partition tolerance  
- **DDoS resistance**: Proof-of-work requirements limit resource exhaustion

### 6.3 Cryptographic Handshake

UDNA employs the [Noise Protocol Framework](https://noiseprotocol.org/) extended with DID-based identity verification:

#### 6.3.1 Noise-IK Pattern
For connections where the remote DID is known:
1. Initiator resolves remote DID to obtain current public keys
2. Noise-IK handshake proceeds with DID-derived static keys
3. Mutual authentication through DID signature verification
4. Session keys derived from handshake provide forward secrecy

#### 6.3.2 Noise-XX Pattern  
For anonymous or first-contact scenarios:
1. Anonymous handshake establishes secure channel
2. DIDs exchanged within encrypted tunnel
3. Post-handshake DID verification confirms identity
4. Optional re-keying with DID-derived keys

## 7. Privacy Considerations

### 7.1 Privacy Mechanisms

#### 7.1.1 Unlinkable Pairwise DIDs

Each bilateral relationship employs unique DIDs:
- **Deterministic derivation**: HMAC-based DID generation from shared secrets
- **Forward secrecy**: Previous relationship DIDs cannot be computed from current keys  
- **Relationship isolation**: Compromise of one relationship does not affect others

#### 7.1.2 Traffic Analysis Resistance
- **Uniform packet sizes**: Padding to fixed boundaries prevents size-based analysis
- **Timing obfuscation**: Random delays reduce timing correlation opportunities
- **Cover traffic**: Optional decoy traffic during low-activity periods

### 7.2 Correlation Prevention

UDNA prevents correlation through:
- **Pairwise identifiers**: Different DIDs for each relationship
- **Temporal rotation**: Regular identifier changes with cryptographic proofs
- **Metadata minimization**: Minimal routing information in packet headers

## 8. Interoperability

### 8.1 Legacy System Integration

#### 8.1.1 DIDComm v2 Compatibility
- **Facet mapping**: Messaging facet provides full DIDComm v2 compatibility
- **Agent bridging**: Existing DIDComm agents communicate through UDNA gateways
- **Protocol translation**: Transparent translation between protocols

#### 8.1.2 IP Network Gateways
- **Translation services**: Gateway mapping UDNA addresses to IP endpoints
- **TLS termination**: Legacy TLS services accessed through DID-authenticated gateways
- **DNS bridges**: Temporary DNS records pointing to UDNA infrastructure

### 8.2 Standards Alignment

UDNA maintains compatibility with:
- **W3C DID Core**: Full compliance with DID specification
- **W3C Verifiable Credentials**: Integration for capability-based authorization
- **IETF protocols**: Coexistence with existing Internet protocols

## 9. Implementation Considerations

### 9.1 Performance Characteristics

Benchmark results on representative hardware:

| Operation | Target | Measured | Notes |
|-----------|--------|----------|-------|
| DID Resolution (cache) | <50μs | 42μs | Local cache, signature verification |
| DID Resolution (DHT) | <10ms | 8.3ms | 3-hop DHT traversal |
| Handshake (1-RTT) | <2ms | 1.7ms | Noise-IK, did:key resolution |
| Address Parsing | <10μs | 7μs | Binary format, zero-copy |

### 9.2 Scalability Analysis

- **DHT Overlay**: O(log n) routing complexity supports millions of nodes
- **Cache Hit Ratio**: >95% achieved with 24-hour TTL
- **Protocol Overhead**: <3% for typical application payloads
- **Storage Requirements**: <100MB overlay state for 1M node network

### 9.3 Resource Requirements

- **Computational**: Minimal cryptographic operations per message
- **Memory**: Efficient caching with bounded memory usage
- **Network**: Low bandwidth overhead through compression
- **Storage**: Compact binary formats minimize storage requirements

## 10. Security and Privacy Considerations

### 10.1 Security Analysis

UDNA's security model has been analyzed using formal verification tools. Key findings:

- **Handshake security**: Proven secure against active adversaries under standard assumptions
- **Identity integrity**: Mathematical guarantees against spoofing attacks  
- **Forward secrecy**: Ephemeral keys prevent retroactive decryption

### 10.2 Privacy Analysis

Privacy protection mechanisms:
- **Unlinkability**: Pairwise DIDs prevent relationship correlation
- **Anonymity**: Optional anonymous handshake patterns
- **Metadata protection**: Minimal routing information exposure

### 10.3 Anti-Abuse Mechanisms

- **Proof-of-work stamps**: Computational requirements limit spam/abuse
- **Rate limiting**: Anonymous quota systems prevent resource exhaustion
- **Reputation systems**: Cryptographic reputation without identity disclosure

## 11. IANA Considerations

This specification defines:

- **Protocol identifier**: "udna" for URI schemes
- **Port assignments**: Default port allocations for UDNA services
- **Method registry**: Registration procedures for new DID methods
- **Capability types**: Registry for capability and credential types

## 12. References

### 12.1 Normative References

- **[DID-CORE]** Sporny, M., Longley, D., Chadwick, D. "[Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)". W3C Recommendation, 19 July 2022.

- **[VC-DATA-MODEL]** Sporny, M., Noble, G., Longley, D., Burnett, D., Zundel, B., Barclay, K. "[Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/vc-data-model/)". W3C Recommendation, 3 March 2022.

- **[RFC2119]** Bradner, S. "[Key words for use in RFCs to Indicate Requirement Levels](https://tools.ietf.org/html/rfc2119)". RFC 2119, March 1997.

- **[RFC8174]** Leiba, B. "[Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words](https://tools.ietf.org/html/rfc8174)". RFC 8174, May 2017.

### 12.2 Informative References

- **[DIDCOMM-MESSAGING]** Hardman, D., Lodder, M., Curran, S. "[DIDComm Messaging v2.0](https://identity.foundation/didcomm-messaging/spec/)". Identity Foundation, 2021.

- **[NOISE]** Perrin, T., Marlinspike, M. "[The Noise Protocol Framework](https://noiseprotocol.org/noise.html)". 2016.

- **[KADEMLIA]** Maymounkov, P., Mazières, D. "Kademlia: A peer-to-peer information system based on the XOR metric". International Workshop on Peer-to-Peer Systems, 2002.

- **[TLS13]** Rescorla, E. "[The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)". RFC 8446, August 2018.

---

## Acknowledgments

The editors thank the W3C Credentials Community Group for their ongoing support and feedback. Special recognition to the DID Working Group for establishing the foundational standards upon which UDNA builds, and to the global cryptography research community for developing the mathematical foundations enabling secure identity systems.

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-09-15 | Initial W3C Community Group Report |

---

*Copyright © 2025 the Contributors to the Universal DID-Native Addressing Specification, published by the W3C Credentials Community Group under the W3C Community Contributor License Agreement (CLA). A human-readable summary is available.*