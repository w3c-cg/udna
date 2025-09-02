
# Universal DID-Native Addressing (UDNA)

UDNA: Universal DID-Native Addressing
UDNA is a new network architecture that fundamentally re-imagines how we address, route, and authenticate network endpoints. Instead of relying on the legacy Internet's location-based addressing (IP addresses), UDNA uses Decentralized Identifiers (DIDs) as the core network primitive. This creates a secure, resilient, and privacy-centric foundation for the next generation of digital infrastructure.

Why UDNA?
The Internet's foundational protocols are a product of a simpler, more trusting era. They suffer from three core crises:

The Identity Crisis: IP addresses describe location, not identity, creating a semantic gap that requires fragile, layered solutions.

The Trust Crisis: Certificate authorities and DNS hierarchies are centralized points of failure, making the network vulnerable to compromise and censorship.

The Privacy Crisis: Location-based addressing enables mass surveillance and network-level correlation by design.

UDNA resolves these issues by making cryptographic identity the primary network primitive, enabling a truly Zero Trust Architecture from the ground up.

Key Features
Identity-as-Address: Every network endpoint is directly identified by a self-sovereign DID, eliminating the need for complex overlay systems.

Cryptographic Verifiability: All addressing and routing operations are cryptographically verifiable at the protocol level, without relying on centralized third parties.

Privacy by Default: UDNA employs Pairwise DIDs and Rotating DIDs to prevent correlation and tracking, ensuring user privacy by design.

High Performance: Designed for demanding, low-latency applications, UDNA achieves sub-50μs DID resolution and <2ms handshake latency.

Decentralized Resilience: A multi-tier, distributed resolution network ensures high availability and resistance to denial-of-service attacks.

Protocol-Native Integration: UDNA is seamlessly integrated as a core component of the Sirraya Codon Protocol (SCP), a purpose-built, next-generation protocol stack.

Getting Started
UDNA is currently in active development. Our reference implementation is being built in Rust to ensure performance and security.

To get started with the project:

Clone the repository:

git clone [https://github.com/SirrayaLabs/UDNA.git](https://github.com/SirrayaLabs/UDNA.git)
cd UDNA


Explore the code: Check out the src/ directory for the core implementation.

Read the documentation: Refer to the docs/ folder for a detailed breakdown of the architecture, protocol specifications, and design principles.

Roadmap
This project is being developed in a phased approach, as detailed in our technical paper.

Milestone 0: Foundation (M0) - COMPLETED

Core UDNA primitives (did:key support), local caching, and basic handshake.

Milestone 1: Network Layer (M1) - IN PROGRESS

Distributed resolution network (DHT), relay contracts for NAT traversal, and cryptographic rotation proofs.

Milestone 2: Production Readiness (M2) - Upcoming

did:scp method, recovery systems, and full DIDComm v2 compatibility.

Milestone 3: Ecosystem Integration (M3) - Upcoming

Legacy IP/TLS gateways, cloud service mesh integration, and comprehensive developer tools.

Contributing
We welcome contributions from the community! Please read our CONTRIBUTING.md for guidelines on how to submit issues, pull requests, and get involved in the discussion.

License
This project is licensed under the 

PlaceholderLicenseName
 - see the LICENSE.md file for details.

For a complete technical overview, please refer to our full paper, "Universal DID-Native Addressing (UDNA): A Cryptographic Foundation for Post-Internet Infrastructure."
