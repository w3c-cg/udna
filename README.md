


# Universal DID-Native Addressing (UDNA)

<div align="center">

![UDNA Banner](https://img.shields.io/badge/UDNA-Universal%20DID--Native%20Addressing-0066cc?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTIgMmMtLjYzIDAtMS4xOS4zNS0xLjQ5Ljg4TDAgMjJoMjQuMDAxYy0uOTItNS41Ny0zLjU0LTEwLjI5LTcuNjg1LTEzLjItLjY3LS4zNS0xLjUxLjEtMS44Ni43Ny0uMzUuNjcuMSAxLjUxLjc3IDEuODZDMTkuNTUgMTEuNyAyMS43IDE1LjkyIDIyIDIySDUuNkw2LjUgMTZIMThsMi4zMi0zLjI2Yy42NC0uOTIuMS0yLjE5LS44OC0yLjY4bC0zLjc2LTEuODgtMS42Ny0zLjI5Yy0uMjktLjYtLjg5LS45OS0xLjU3LS44M2gtLjAyYy0uNjkuMTUtMS4yMi42OS0xLjM4IDEuMzZMOS4yNSA5aC0uMDJjLS42NS4wOS0xLjE3LjU4LTEuMjUgMS4yM0w2IDIwLjkyIDEuMTIgMTZjLS42MS0uNjEtLjU0LTEuNjQuMTUtMi4yM2w0LjgtNC44Yy42Mi0uNjIgMS42NC0uNTYgMi4yMi4xNWwxLjI4IDEuNTQgMS4wMi0xLjU0Yy42NC0uOTYgMS45MS0xLjI2IDIuODctLjYybDEuNjcgMS4xIDMuMzItLjgzYzEuMTItLjI4IDIuMjguMTIgMy4wOC45M2wxLjUgMS41Yy42Mi42MiAxLjY0LjU2IDIuMjItLjE1bC40NS0uNDVjLjYyLS42Mi41Ni0xLjY0LS4xNS0yLjIybC0yLjQ3LTIuNDctLjIyLS4yMmMtLjk5LS45OS0yLjM0LTEuMzYtMy42Mi0xLjAybC0zLjU3Ljg5LTIuNS0zLjc2Yy0uNS0uNzUtMS40Mi0xLjE2LTIuMzItLjk1aC0uMDJjLS44OS4yLTEuNTQuODUtMS43NSAxLjc0TDMuMzQgNC4xMmMtLjUuNzUtLjA1IDEuNjkuNyAyLjE5bDQuOCAyLjRMMTIgMTkuMWwxLjA0LTIuMTIgMS41NCAxLjAzYy45OC42NSAyLjI1LjQyIDIuOS0uNTZsMi4zNi0zLjM2Yy42NS0uOTguNDItMi4yNS0uNTYtMi45bC0xLjg0LTEuMjQgMi40LTIuNGMuNTgtLjU4LjU4LTEuNTQgMC0yLjEyLS41OC0uNTgtMS41NC0uNTgtMi4xMiAwbC00Ljk1IDQuOTVjLS41OC41OC0uNTggMS41NCAwIDIuMTIuNTguNTggMS41NC41OCAyLjEyIDBsLjU4LS41OCAxLjA2IDIuMTIgMS41NC0zLjA4Yy4yNS0uNS43NS0uODQgMS4zMS0uODRoNC44MmMuNTcgMCAxLjA4LjM0IDEuMzMuODRsMS42NiAzLjMyYy41Ljk5LS4wNyAyLjE4LTEuMDYgMi42OGwtNS42MiAyLjgxYy0uNDguMjQtMS4wNC4zNi0xLjYuMzZoLTEuMDJjLS41NiAwLTEuMTItLjEyLTEuNi0uMzZsLTUuNjItMi44MWMtLjk5LS41LTEuNTYtMS42OS0xLjA2LTIuNjhsMS42Ni0zLjMyYy4yNS0uNS43NS0uODQgMS4zMy0uODRoNC44MmMuNTYgMCAxLjA2LjM0IDEuMzEuODRsMS41NCAzLjA4LjU4LS41OGMuNTgtLjU4IDEuNTQtLjU4IDIuMTIgMCAuNTguNTguNTggMS41NCAwIDIuMTJsLTQuOTUgNC45NWMtLjU4LjU4LTEuNTQuNTgtMi4xMiAwLS41OC0uNTgtLjU4LTEuNTQgMC0yLjEybDIuNC0yLjQtMS44NC0xLjI0Yy0uOTgtLjY1LTIuMjUtLjQyLTIuOS41NmwtMi4zNiAzLjM2Yy0uNjUuOTgtLjQyIDIuMjUuNTYgMi45bDEuNTQgMS4wMyAxLjA0LTIuMTIgMy4wNi02LjEyIDQuOCAyLjRjLjc1LjUgMS42OS4wNSAyLjE5LS43bDEuMjItMi40NGMuMi0uODkuODUtMS41NCAxLjc0LTEuNzVoLjAyYy45LS4yMSAxLjgyLjIgMi4zMi45NWwyLjUgMy43NiAzLjU3LS44OWMxLjI4LS4zMiAyLjYzLjAzIDMuNjIgMS4wMmwuMjIuMjIgMi40NyAyLjQ3Yy43MS43MS43NyAxLjYuMTUgMi4yMmwtLjQ1LjQ1Yy0uNTguNTgtMS42LjQ3LTIuMjItLjE1bC0xLjUtMS41Yy0uOC0uOC0xLjk2LTEuMjEtMy4wOC0uOTNsLTMuMzIuODMtMS42Ny0xLjFjLS45Ni0uNjQtMi4yMy0uMzQtMi44Ny42MmwtMS4wMiAxLjU0LTEuMjgtMS41NGMtLjU4LS43MS0xLjYtLjc3LTIuMjItLjE1bC00LjggNC44Yy0uNjkuNTktLjc2IDEuNjItLjE1IDIuMjNMNiAyMC45MiA3Ljk4IDkuMzhjLjA4LS42NS42LTEuMTQgMS4yNS0xLjIzaC4wMkM5Ljg5IDggMTAuNDIgNy40NiAxMS4xIDcuMzFsLjAyLjdjLjE2LS42Ny42OS0xLjIxIDEuMzgtMS4zNmgwYy42OC0uMTYgMS4yOC4yMyAxLjU3LjgzbDEuNjcgMy4yOSAzLjc2IDEuODhjLjk4LjQ5IDEuNTIgMS43Ni44OCAyLjY4TDE4IDE2SDYuNUw1LjYgMjJIMjJsLTEwLjUxLTE5LjEyYy0uMy0uNTMtLjg2LS44OC0xLjQ5LS44OHoiIGZpbGw9IiNmZmYiLz48L3N2Zz4=)
![W3C Community Group](https://img.shields.io/badge/W3C-Community%20Group-005a9c?style=for-the-badge&logo=w3c&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active%20Development-27ae60?style=for-the-badge&logo=git&logoColor=white)

**Building the identity-native Internet. A paradigm shift from location-based to identity-based networking.**

[![Join W3C Group](https://img.shields.io/badge/Join-W3C%20Community%20Group-0066cc?style=for-the-badge&logo=w3c&logoColor=white)](https://www.w3.org/community/udna/)
[![GitHub Stars](https://img.shields.io/github/stars/w3c-udna/udna?style=for-the-badge&logo=github&logoColor=white)](https://github.com/w3c-udna/udna/stargazers)
[![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/w3c-udna/udna/discussions)
[![License](https://img.shields.io/badge/License-Apache%202.0-ff69b4?style=for-the-badge&logo=apache&logoColor=white)](LICENSE)

</div>

## <img src="https://img.shields.io/badge/-Table%20of%20Contents-0066cc?style=flat-square&logo=readme&logoColor=white" /> Table of Contents

- <img src="https://img.shields.io/badge/-Overview-27ae60?style=flat-square&logo=target&logoColor=white" /> [Overview](#overview)
- <img src="https://img.shields.io/badge/-Why%20UDNA-0066cc?style=flat-square&logo=rocket&logoColor=white" /> [Why UDNA?](#why-udna)
- <img src="https://img.shields.io/badge/-Architecture-9b59b6?style=flat-square&logo=diagram-project&logoColor=white" /> [Architecture](#architecture)
- <img src="https://img.shields.io/badge/-Key%20Features-f39c12?style=flat-square&logo=star&logoColor=white" /> [Key Features](#key-features)
- <img src="https://img.shields.io/badge/-Getting%20Started-3498db?style=flat-square&logo=box&logoColor=white" /> [Getting Started](#getting-started)
- <img src="https://img.shields.io/badge/-Contributing-e74c3c?style=flat-square&logo=hands-helping&logoColor=white" /> [Contributing](#contributing)
- <img src="https://img.shields.io/badge/-Documentation-2ecc71?style=flat-square&logo=book&logoColor=white" /> [Documentation](#documentation)
- <img src="https://img.shields.io/badge/-Community-1abc9c?style=flat-square&logo=calendar-alt&logoColor=white" /> [Community](#community)
- <img src="https://img.shields.io/badge/-License-34495e?style=flat-square&logo=balance-scale&logoColor=white" /> [License](#license)

## <img src="https://img.shields.io/badge/-Overview-27ae60?style=flat-square&logo=target&logoColor=white" /> Overview

<div align="center">

**Universal DID-Native Addressing (UDNA)** is a next-generation networking protocol that makes cryptographic identity the foundational addressing mechanism for all digital communication.

</div>

UDNA represents a fundamental architectural shift from traditional **location-based addressing** (IP addresses, URLs) to **identity-based addressing** using W3C Decentralized Identifiers (DIDs). This enables secure, private, and self-sovereign communication at global scale.

### The Vision

> "To create an Internet where identity is native to addressing, not an afterthought."

| Traditional Internet | UDNA Internet |
|---------------------|---------------|
| <img src="https://img.shields.io/badge/-Location--based-005a9c?style=flat-square&logo=map-marker-alt&logoColor=white" /> **Location-based** (IP addresses) | <img src="https://img.shields.io/badge/-Identity--based-27ae60?style=flat-square&logo=fingerprint&logoColor=white" /> **Identity-based** (DIDs) |
| <img src="https://img.shields.io/badge/-Bolt--on%20Security-9b59b6?style=flat-square&logo=link&logoColor=white" /> **Bolt-on security** (TLS, VPNs) | <img src="https://img.shields.io/badge/-Built--in%20Security-0066cc?style=flat-square&logo=lock&logoColor=white" /> **Built-in security** (cryptographic identity) |
| <img src="https://img.shields.io/badge/-Privacy%20by%20Accident-e74c3c?style=flat-square&logo=eye&logoColor=white" /> **Privacy by accident** | <img src="https://img.shields.io/badge/-Privacy%20by%20Design-00b894?style=flat-square&logo=user-shield&logoColor=white" /> **Privacy by design** |
| <img src="https://img.shields.io/badge/-Centralized%20Coordination-34495e?style=flat-square&logo=globe&logoColor=white" /> **Centralized coordination** (DNS, CAs) | <img src="https://img.shields.io/badge/-Decentralized%20Operation-f39c12?style=flat-square&logo=bolt&logoColor=white" /> **Decentralized operation** |

## <img src="https://img.shields.io/badge/-Why%20UDNA-0066cc?style=flat-square&logo=rocket&logoColor=white" /> Why UDNA?

### The Problem with Current Internet Architecture

<table>
<tr>
<th width="50%"><img src="https://img.shields.io/badge/-Current%20Limitations-e74c3c?style=flat-square&logo=exclamation-triangle&logoColor=white" /></th>
<th width="50%"><img src="https://img.shields.io/badge/-UDNA%20Solution-27ae60?style=flat-square&logo=check-circle&logoColor=white" /></th>
</tr>
<tr>
<td>

- <img src="https://img.shields.io/badge/-Fragmented%20Identity%20Systems-9b59b6?style=flat-square&logo=puzzle-piece&logoColor=white" /> **Fragmented identity systems** across services
- <img src="https://img.shields.io/badge/-Centralized%20Trust%20Dependencies-34495e?style=flat-square&logo=server&logoColor=white" /> **Centralized trust dependencies** (CAs, DNS)
- <img src="https://img.shields.io/badge/-Metadata%20Leakage-f39c12?style=flat-square&logo=user-secret&logoColor=white" /> **Metadata leakage** and surveillance risks
- <img src="https://img.shields.io/badge/-Complex%20Authentication-e74c3c?style=flat-square&logo=key&logoColor=white" /> **Complex authentication** requiring separate systems
- <img src="https://img.shields.io/badge/-Vendor%20Lock--in-005a9c?style=flat-square&logo=lock&logoColor=white" /> **Vendor lock-in** to specific identity providers
- <img src="https://img.shields.io/badge/-No%20Service%20Discovery-27ae60?style=flat-square&logo=search&logoColor=white" /> **No standard way** for services to discover each other

</td>
<td>

- <img src="https://img.shields.io/badge/-Unified%20Identity%20Layer-0066cc?style=flat-square&logo=layer-group&logoColor=white" /> **Unified identity layer** using W3C DIDs
- <img src="https://img.shields.io/badge/-Decentralized%20Trust-9b59b6?style=flat-square&logo=network-wired&logoColor=white" /> **Decentralized trust** via cryptographic verification
- <img src="https://img.shields.io/badge/-Privacy--Preserving-00b894?style=flat-square&logo=user-shield&logoColor=white" /> **Privacy-preserving** with pairwise identifiers
- <img src="https://img.shields.io/badge/-Native%20Authentication-27ae60?style=flat-square&logo=fingerprint&logoColor=white" /> **Native authentication** built into addressing
- <img src="https://img.shields.io/badge/-Self--Sovereign%20Control-005a9c?style=flat-square&logo=crown&logoColor=white" /> **Self-sovereign control** over digital identity
- <img src="https://img.shields.io/badge/-Built--in%20Service%20Discovery-0066cc?style=flat-square&logo=search-plus&logoColor=white" /> **Built-in service discovery** through DID documents

</td>
</tr>
</table>

### Real-World Impact

| Use Case | Traditional Approach | UDNA Approach |
|----------|-------------------|---------------|
| <img src="https://img.shields.io/badge/-Healthcare-27ae60?style=flat-square&logo=heartbeat&logoColor=white" /> **Healthcare** | Separate logins per provider, faxed records | Single DID, encrypted record sharing |
| <img src="https://img.shields.io/badge/-IoT%20Networks-0066cc?style=flat-square&logo=network-wired&logoColor=white" /> **IoT Networks** | Proprietary protocols, cloud dependencies | Device-to-device secure communication |
| <img src="https://img.shields.io/badge/-Enterprise%20APIs-9b59b6?style=flat-square&logo=building&logoColor=white" /> **Enterprise APIs** | API keys, OAuth tokens, complex auth | DID-based addressing with fine-grained capabilities |
| <img src="https://img.shields.io/badge/-Financial%20Services-f39c12?style=flat-square&logo=money-check-alt&logoColor=white" /> **Financial Services** | KYC duplication, siloed identity systems | Portable verifiable credentials |

## <img src="https://img.shields.io/badge/-Architecture-9b59b6?style=flat-square&logo=diagram-project&logoColor=white" /> Architecture

### Core Components

```mermaid
graph TB
    A[Applications] --> B[UDNA Layer]
    B --> C{Transport Layer}
    C --> D[TCP/IP]
    
    subgraph "UDNA Layer"
        B1[<img src='https://img.shields.io/badge/Addressing-00b894?style=flat-square&logo=map-marker-alt&logoColor=white' />]
        B2[<img src='https://img.shields.io/badge/Resolution-9b59b6?style=flat-square&logo=search&logoColor=white' />]
        B3[<img src='https://img.shields.io/badge/Messaging-f39c12?style=flat-square&logo=comments&logoColor=white' />]
        B4[<img src='https://img.shields.io/badge/Security-e74c3c?style=flat-square&logo=shield-alt&logoColor=white' />]
        
        B1 --> B2
        B2 --> B3
        B3 --> B4
    end
    
    style B fill:#0066cc,stroke:#fff,stroke-width:2px
    style B1 fill:#00b894,stroke:#fff
    style B2 fill:#9b59b6,stroke:#fff
    style B3 fill:#f39c12,stroke:#fff
    style B4 fill:#e74c3c,stroke:#fff
```

### 1. <img src="https://img.shields.io/badge/-Addressing%20Layer-00b894?style=flat-square&logo=map-marker-alt&logoColor=white" /> **Addressing Layer**
- **UDNA URI Format**: `udna://did:method/path#fragment`
- **DID Integration**: Native support for all W3C DID methods
- **Service Discovery**: Embedded in DID documents
- **Capability URLs**: Fine-grained access control

### 2. <img src="https://img.shields.io/badge/-Resolution%20Layer-9b59b6?style=flat-square&logo=search&logoColor=white" /> **Resolution Layer**
- **Multi-tier caching**: Local → P2P → Authoritative
- **Performance targets**: <10ms cached, <200ms network
- **Fallback strategies**: Graceful degradation
- **Load balancing**: Intelligent endpoint selection

### 3. <img src="https://img.shields.io/badge/-Messaging%20Layer-f39c12?style=flat-square&logo=comments&logoColor=white" /> **Messaging Layer**
- **DIDComm v2 integration**: End-to-end encrypted messaging
- **Multi-transport support**: HTTP, WebSockets, WebRTC
- **Forward secrecy**: Session key rotation
- **Message queuing**: Reliable delivery guarantees

### 4. <img src="https://img.shields.io/badge/-Security%20Layer-e74c3c?style=flat-square&logo=shield-alt&logoColor=white" /> **Security Layer**
- **Zero-trust model**: Verify everything
- **Capability-based access**: Fine-grained permissions
- **Privacy preservation**: Pairwise DIDs, correlation resistance
- **Audit logging**: Comprehensive security monitoring

## <img src="https://img.shields.io/badge/-Key%20Features-f39c12?style=flat-square&logo=star&logoColor=white" /> Key Features

### <img src="https://img.shields.io/badge/-Security%20First-e74c3c?style=flat-square&logo=shield-alt&logoColor=white" /> **Security First**
<div align="center">

| Feature | Description | Status |
|---------|-------------|--------|
| <img src="https://img.shields.io/badge/-End--to--End%20Encryption-0066cc?style=flat-square&logo=lock&logoColor=white" /> **End-to-End Encryption** | All communications encrypted by default | ![Implemented](https://img.shields.io/badge/-✅%20Implemented-27ae60?style=flat-square) |
| <img src="https://img.shields.io/badge/-Cryptographic%20Verification-9b59b6?style=flat-square&logo=key&logoColor=white" /> **Cryptographic Verification** | Every message and endpoint verified | ![Implemented](https://img.shields.io/badge/-✅%20Implemented-27ae60?style=flat-square) |
| <img src="https://img.shields.io/badge/-Forward%20Secrecy-00b894?style=flat-square&logo=forward&logoColor=white" /> **Forward Secrecy** | Session keys rotated regularly | ![Implemented](https://img.shields.io/badge/-✅%20Implemented-27ae60?style=flat-square) |
| <img src="https://img.shields.io/badge/-Zero--Trust%20Model-f39c12?style=flat-square&logo=user-shield&logoColor=white" /> **Zero-Trust Model** | No implicit trust, everything verified | ![In Progress](https://img.shields.io/badge/-🚧%20In%20Progress-f39c12?style=flat-square) |

</div>

### <img src="https://img.shields.io/badge/-High%20Performance-0066cc?style=flat-square&logo=tachometer-alt&logoColor=white" /> **High Performance**
- <img src="https://img.shields.io/badge/-Sub--50μs%20Resolution-27ae60?style=flat-square&logo=bolt&logoColor=white" /> **Sub-50μs resolution** for cached DIDs
- <img src="https://img.shields.io/badge/-<2ms%20Handshake-0066cc?style=flat-square&logo=handshake&logoColor=white" /> **<2ms handshake** latency
- <img src="https://img.shields.io/badge/-Millions%20of%20Connections-9b59b6?style=flat-square&logo=users&logoColor=white" /> **Millions of concurrent** connections
- <img src="https://img.shields.io/badge/-Efficient%20Protocols-00b894?style=flat-square&logo=code&logoColor=white" /> **Efficient binary protocols** for low bandwidth

### <img src="https://img.shields.io/badge/-Interoperability-27ae60?style=flat-square&logo=handshake&logoColor=white" /> **Interoperability**
- <img src="https://img.shields.io/badge/-W3C%20DID%20Core%201.0-005a9c?style=flat-square&logo=w3c&logoColor=white" /> **W3C DID Core 1.0** compliant
- <img src="https://img.shields.io/badge/-DIDComm%20v2-0066cc?style=flat-square&logo=comments&logoColor=white" /> **DIDComm v2** messaging support
- <img src="https://img.shields.io/badge/-Legacy%20Protocol%20Bridges-9b59b6?style=flat-square&logo=bridge&logoColor=white" /> **Legacy protocol** bridges (HTTP, WebSocket)
- <img src="https://img.shields.io/badge/-Multiple%20DID%20Methods-27ae60?style=flat-square&logo=th-large&logoColor=white" /> **Multiple DID method** support (`did:key`, `did:web`, `did:ion`)

### <img src="https://img.shields.io/badge/-Scalability-9b59b6?style=flat-square&logo=network-wired&logoColor=white" /> **Scalability**
- <img src="https://img.shields.io/badge/-Distributed%20Resolution%20Networks-0066cc?style=flat-square&logo=globe&logoColor=white" /> **Distributed resolution** networks
- <img src="https://img.shields.io/badge/-Peer--to--Peer%20Caching-00b894?style=flat-square&logo=users&logoColor=white" /> **Peer-to-peer caching** layers
- <img src="https://img.shields.io/badge/-Horizontal%20Scaling-f39c12?style=flat-square&logo=expand-arrows-alt&logoColor=white" /> **Horizontal scaling** architecture
- <img src="https://img.shields.io/badge/-Global%20Deployment-005a9c?style=flat-square&logo=globe-americas&logoColor=white" /> **Global deployment** ready

## <img src="https://img.shields.io/badge/-Getting%20Started-3498db?style=flat-square&logo=box&logoColor=white" /> Getting Started

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/w3c-udna/udna.git
cd udna

# 2. Install dependencies
npm install
# or
yarn install

# 3. Run the development server
npm run dev
# or
yarn dev

# 4. Open your browser
# http://localhost:3000
```

### Installation Options

<details>
<summary><img src="https://img.shields.io/badge/-Package%20Managers-27ae60?style=flat-square&logo=npm&logoColor=white" /> <strong>Package Managers</strong></summary>

```bash
# NPM
npm install @udna/core @udna/client

# Yarn
yarn add @udna/core @udna/client

# PNPM
pnpm add @udna/core @udna/client
```

</details>

<details>
<summary><img src="https://img.shields.io/badge/-Browser%20(CDN)-0066cc?style=flat-square&logo=chrome&logoColor=white" /> <strong>Browser (CDN)</strong></summary>

```html
<script src="https://unpkg.com/@udna/client@latest/dist/browser.min.js"></script>
<script>
  // UDNA is now available as window.UDNA
  const client = new UDNA.Client({ /* config */ });
</script>
```

</details>

<details>
<summary><img src="https://img.shields.io/badge/-Docker-3498db?style=flat-square&logo=docker&logoColor=white" /> <strong>Docker</strong></summary>

```bash
# Pull the latest image
docker pull ghcr.io/w3c-udna/udna:latest

# Run the container
docker run -p 3000:3000 ghcr.io/w3c-udna/udna:latest
```

</details>

### Basic Usage Example

```javascript
import { UDNAClient } from '@udna/client';

// Initialize client
const client = new UDNAClient({
  did: 'did:key:z6Mkf5rGMontZ2S6qpnYLAJ3NjBhqXjJcFkNxTvNM7pAqkPc',
  resolver: {
    endpoints: ['https://resolver.udna.dev'],
    cacheTtl: 3600
  }
});

// Resolve a UDNA address
const endpoint = await client.resolve(
  'udna://did:web:api.example.com/services/chat'
);

// Send a secure message
const response = await client.sendMessage({
  to: endpoint,
  type: 'application/json',
  body: { message: 'Hello UDNA!' }
});

console.log('Response:', response);
```

### Framework Integrations

| Framework | Package | Status | Documentation |
|-----------|---------|--------|---------------|
| <img src="https://img.shields.io/badge/-React-61DAFB?style=flat-square&logo=react&logoColor=white" /> **React** | `@udna/react` | ![Stable](https://img.shields.io/badge/-✅%20Stable-27ae60?style=flat-square) | [Docs](https://udna.dev/docs/react) |
| <img src="https://img.shields.io/badge/-Vue.js-4FC08D?style=flat-square&logo=vue.js&logoColor=white" /> **Vue.js** | `@udna/vue` | ![Stable](https://img.shields.io/badge/-✅%20Stable-27ae60?style=flat-square) | [Docs](https://udna.dev/docs/vue) |
| <img src="https://img.shields.io/badge/-Angular-DD0031?style=flat-square&logo=angular&logoColor=white" /> **Angular** | `@udna/angular` | ![Beta](https://img.shields.io/badge/-🚧%20Beta-f39c12?style=flat-square) | [Docs](https://udna.dev/docs/angular) |
| <img src="https://img.shields.io/badge/-Node.js-339933?style=flat-square&logo=node.js&logoColor=white" /> **Node.js** | `@udna/server` | ![Stable](https://img.shields.io/badge/-✅%20Stable-27ae60?style=flat-square) | [Docs](https://udna.dev/docs/node) |
| <img src="https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white" /> **Python** | `udna-py` | ![Alpha](https://img.shields.io/badge/-⚡%20Alpha-9b59b6?style=flat-square) | [Docs](https://udna.dev/docs/python) |
| <img src="https://img.shields.io/badge/-Go-00ADD8?style=flat-square&logo=go&logoColor=white" /> **Go** | `go-udna` | ![Alpha](https://img.shields.io/badge/-⚡%20Alpha-9b59b6?style=flat-square) | [Docs](https://udna.dev/docs/go) |

## <img src="https://img.shields.io/badge/-Contributing-e74c3c?style=flat-square&logo=hands-helping&logoColor=white" /> Contributing

We welcome contributions from everyone! Here's how you can help:

### Ways to Contribute

<table>
<tr>
<td width="33%" align="center">

#### <img src="https://img.shields.io/badge/-Report%20Bugs-e74c3c?style=flat-square&logo=bug&logoColor=white" /> **Report Bugs**
Found an issue? Let us know!

[![Report Bug](https://img.shields.io/badge/Report-Bug-e74c3c?style=for-the-badge&logo=bug&logoColor=white)](https://github.com/w3c-udna/udna/issues/new?template=bug_report.md)

</td>
<td width="33%" align="center">

#### <img src="https://img.shields.io/badge/-Suggest%20Features-9b59b6?style=flat-square&logo=lightbulb&logoColor=white" /> **Suggest Features**
Have an idea? Share it with us!

[![Request Feature](https://img.shields.io/badge/Request-Feature-9b59b6?style=for-the-badge&logo=lightbulb&logoColor=white)](https://github.com/w3c-udna/udna/issues/new?template=feature_request.md)

</td>
<td width="33%" align="center">

#### <img src="https://img.shields.io/badge/-Write%20Documentation-3498db?style=flat-square&logo=readme&logoColor=white" /> **Write Documentation**
Help improve our docs!

[![Improve Docs](https://img.shields.io/badge/Improve-Docs-3498db?style=for-the-badge&logo=readme&logoColor=white)](https://github.com/w3c-udna/documentation)

</td>
</tr>
</table>

### Development Workflow

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Commit your changes**
   ```bash
   git commit -m 'Add amazing feature'
   ```
5. **Push to your branch**
   ```bash
   git push origin feature/amazing-feature
   ```
6. **Open a Pull Request**

### Code Standards

- <img src="https://img.shields.io/badge/-TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white" /> **TypeScript** for all new code
- <img src="https://img.shields.io/badge/-ESLint-4B32C3?style=flat-square&logo=eslint&logoColor=white" /> **ESLint** and **Prettier** for code quality
- <img src="https://img.shields.io/badge/-100%%20Test%20Coverage-27ae60?style=flat-square&logo=check-circle&logoColor=white" /> **100% test coverage** for critical paths
- <img src="https://img.shields.io/badge/-Semantic%20Commits-34495e?style=flat-square&logo=git&logoColor=white" /> **Semantic commits** following Conventional Commits
- <img src="https://img.shields.io/badge/-Documentation-2ecc71?style=flat-square&logo=book&logoColor=white" /> **Documentation** for all public APIs

### Good First Issues

Looking for a place to start? Check out these issues:

[![Good First Issues](https://img.shields.io/github/issues/w3c-udna/udna/good%20first%20issue?color=27ae60&label=Good%20First%20Issues&style=for-the-badge&logo=github&logoColor=white)](https://github.com/w3c-udna/udna/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)

## <img src="https://img.shields.io/badge/-Documentation-2ecc71?style=flat-square&logo=book&logoColor=white" /> Documentation

### Comprehensive Guides

| Document | Description | Link |
|----------|-------------|------|
| <img src="https://img.shields.io/badge/-Architecture%20Guide-9b59b6?style=flat-square&logo=diagram-project&logoColor=white" /> **Architecture Guide** | Complete architectural overview | [View](https://udna.dev/docs/architecture) |
| <img src="https://img.shields.io/badge/-API%20Reference-0066cc?style=flat-square&logo=code&logoColor=white" /> **API Reference** | Complete API documentation | [View](https://udna.dev/docs/api) |
| <img src="https://img.shields.io/badge/-Getting%20Started-3498db?style=flat-square&logo=rocket&logoColor=white" /> **Getting Started** | Step-by-step setup guide | [View](https://udna.dev/docs/getting-started) |
| <img src="https://img.shields.io/badge/-Security%20Guide-e74c3c?style=flat-square&logo=shield-alt&logoColor=white" /> **Security Guide** | Security best practices | [View](https://udna.dev/docs/security) |
| <img src="https://img.shields.io/badge/-Performance%20Guide-0066cc?style=flat-square&logo=tachometer-alt&logoColor=white" /> **Performance Guide** | Optimization techniques | [View](https://udna.dev/docs/performance) |

### Specification Documents

| Specification | Status | Version | Links |
|---------------|--------|---------|-------|
| <img src="https://img.shields.io/badge/-UDNA%20Core-0066cc?style=flat-square&logo=cube&logoColor=white" /> **UDNA Core** | ![Draft](https://img.shields.io/badge/-🚧%20Draft-f39c12?style=flat-square) | v0.9 | [Spec](https://udna.dev/spec/core) • [GitHub](https://github.com/w3c-udna/specifications) |
| <img src="https://img.shields.io/badge/-UDNA%20Addressing-00b894?style=flat-square&logo=map-marker-alt&logoColor=white" /> **UDNA Addressing** | ![Draft](https://img.shields.io/badge/-🚧%20Draft-f39c12?style=flat-square) | v0.8 | [Spec](https://udna.dev/spec/addressing) |
| <img src="https://img.shields.io/badge/-UDNA%20Resolution-9b59b6?style=flat-square&logo=search&logoColor=white" /> **UDNA Resolution** | ![Draft](https://img.shields.io/badge/-🚧%20Draft-f39c12?style=flat-square) | v0.7 | [Spec](https://udna.dev/spec/resolution) |
| <img src="https://img.shields.io/badge/-UDNA%20Messaging-f39c12?style=flat-square&logo=comments&logoColor=white" /> **UDNA Messaging** | ![Draft](https://img.shields.io/badge/-🚧%20Draft-f39c12?style=flat-square) | v0.8 | [Spec](https://udna.dev/spec/messaging) |

### Tutorials & Examples

| Tutorial | Level | Description |
|----------|-------|-------------|
| <img src="https://img.shields.io/badge/-Build%20a%20Secure%20Chat%20App-27ae60?style=flat-square&logo=comments&logoColor=white" /> **Build a Secure Chat App** | Beginner | End-to-end encrypted messaging |
| <img src="https://img.shields.io/badge/-Enterprise%20API%20Gateway-9b59b6?style=flat-square&logo=building&logoColor=white" /> **Enterprise API Gateway** | Intermediate | DID-based API authentication |
| <img src="https://img.shields.io/badge/-IoT%20Device%20Network-0066cc?style=flat-square&logo=network-wired&logoColor=white" /> **IoT Device Network** | Advanced | Device-to-device communication |
| <img src="https://img.shields.io/badge/-Migration%20from%20OAuth-f39c12?style=flat-square&logo=exchange-alt&logoColor=white" /> **Migration from OAuth** | Intermediate | Transition guide for existing systems |

## <img src="https://img.shields.io/badge/-Community-1abc9c?style=flat-square&logo=calendar-alt&logoColor=white" /> Community

### Join the Conversation

<div align="center">

| Platform | Purpose | Link |
|----------|---------|------|
| <img src="https://img.shields.io/badge/-Mailing%20List-005a9c?style=flat-square&logo=mailchimp&logoColor=white" /> **Mailing List** | Official discussions | [Join](mailto:public-did-native-addr-request@w3.org) |
| <img src="https://img.shields.io/badge/-GitHub%20Discussions-181717?style=flat-square&logo=github&logoColor=white" /> **GitHub Discussions** | Technical Q&A | [Join](https://github.com/w3c-udna/udna/discussions) |
| <img src="https://img.shields.io/badge/-Twitter-1DA1F2?style=flat-square&logo=twitter&logoColor=white" /> **Twitter** | Announcements | [Follow](https://twitter.com/udna_project) |
| <img src="https://img.shields.io/badge/-Blog-FF5722?style=flat-square&logo=blogger&logoColor=white" /> **Blog** | Articles & updates | [Read](https://udna.dev/blog) |

</div>

### Meetings & Events

#### <img src="https://img.shields.io/badge/-Weekly%20Working%20Sessions-27ae60?style=flat-square&logo=calendar-week&logoColor=white" /> **Weekly Working Sessions**
- **When**: Every Tuesday, 15:00 UTC
- **Where**: [Video Conference](https://meet.google.com/xxx-xxxx-xxx)
- **Agenda**: [GitHub Wiki](https://github.com/w3c-udna/udna/wiki/Meetings)

#### <img src="https://img.shields.io/badge/-Monthly%20Community%20Calls-0066cc?style=flat-square&logo=calendar-alt&logoColor=white" /> **Monthly Community Calls**
- **When**: First Thursday of each month, 18:00 UTC
- **Where**: [Live Stream](https://youtube.com/c/UDNAProject)
- **Recordings**: [YouTube Playlist](https://youtube.com/playlist?list=...)

### Upcoming Events

| Event | Date | Location | Description |
|-------|------|----------|-------------|
| <img src="https://img.shields.io/badge/-Internet%20Identity%20Workshop-27ae60?style=flat-square&logo=users&logoColor=white" /> **Internet Identity Workshop** | April 2026 | Online | Workshop on decentralized identity |
| <img src="https://img.shields.io/badge/-W3C%20TPAC%202026-005a9c?style=flat-square&logo=w3c&logoColor=white" /> **W3C TPAC 2026** | September 2026 | Montréal | W3C annual conference |
| <img src="https://img.shields.io/badge/-UDNA%20Hackathon-0066cc?style=flat-square&logo=code&logoColor=white" /> **UDNA Hackathon** | June 2026 | Global | Build UDNA-powered applications |

### Project Governance

UDNA follows the **W3C Community Group Process**:

- <img src="https://img.shields.io/badge/-Consensus--based-27ae60?style=flat-square&logo=handshake&logoColor=white" /> **Consensus-based decision making**
- <img src="https://img.shields.io/badge/-Transparent%20Process-3498db?style=flat-square&logo=eye&logoColor=white" /> **Transparent process** with public records
- <img src="https://img.shields.io/badge/-Inclusive%20Participation-9b59b6?style=flat-square&logo=users&logoColor=white" /> **Inclusive participation** from all stakeholders
- <img src="https://img.shields.io/badge/-IPR%20Protection-34495e?style=flat-square&logo=balance-scale&logoColor=white" /> **IPR protection** under W3C Patent Policy

## <img src="https://img.shields.io/badge/-License-34495e?style=flat-square&logo=balance-scale&logoColor=white" /> License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

This project includes and depends on the following third-party software:

| Software | License | Purpose |
|----------|---------|---------|
| <img src="https://img.shields.io/badge/-libsodium-7247B5?style=flat-square&logo=key&logoColor=white" /> **libsodium** | ISC License | Cryptography primitives |
| <img src="https://img.shields.io/badge/-DID%20Core-005a9c?style=flat-square&logo=w3c&logoColor=white" /> **DID Core** | W3C Software License | DID specifications |
| <img src="https://img.shields.io/badge/-DIDComm%20v2-0066cc?style=flat-square&logo=comments&logoColor=white" /> **DIDComm v2** | Apache 2.0 | Messaging protocol |

### Commercial Use

UDNA is **free for commercial use** under the Apache 2.0 license. Organizations can:

- Use UDNA in proprietary products
- Offer UDNA-based commercial services
- Modify and redistribute UDNA code
- Patent improvements (with patent grant)

---

<div align="center">

## <img src="https://img.shields.io/badge/-Supported%20By-005a9c?style=flat-square&logo=handshake&logoColor=white" /> Supported By

[![W3C](https://img.shields.io/badge/W3C-Member-005a9c?style=for-the-badge&logo=w3c&logoColor=white)](https://www.w3.org)
[![Linux Foundation](https://img.shields.io/badge/Linux%20Foundation-Member-f5f5f5?style=for-the-badge&logo=linuxfoundation&logoColor=black)](https://www.linuxfoundation.org)
[![DIF](https://img.shields.io/badge/DIF-Member-0066cc?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTIgMkM2LjQ4IDIgMiA2LjQ4IDIgMTJzNC40OCAxMCAxMCAxMCAxMC00LjQ4IDEwLTEwUzE3LjUyIDIgMTIgMnptMCAxOGMtNC40MSAwLTgtMy41OS04LThzMy41OS04IDgtOCA4IDMuNTkgOCA4LTMuNTkgOC04IDh6IiBmaWxsPSIjZmZmIi8+PHBhdGggZD0iTTEyIDdjLTIuNzYgMC01IDIuMjQtNSA1czIuMjQgNSA1IDUgNS0yLjI0IDUtNS0yLjI0LTUtNS01em0wIDhjLTEuNjYgMC0zLTEuMzQtMy0zczEuMzQtMyAzLTMgMyAxLjM0IDMgMy0xLjM0IDMtMyAzem0wLTVjLS41NSAwLTEtLjQ1LTEtMXMuNDUtMSAxLTEgMSAuNDUgMSAxLS40NSAxLTEgMXoiIGZpbGw9IiMwMDY2Y2MiLz48L3N2Zz4=)](https://identity.foundation)

## <img src="https://img.shields.io/badge/-Star%20History-f39c12?style=flat-square&logo=star&logoColor=white" /> Star History

[![Star History Chart](https://api.star-history.com/svg?repos=w3c-udna/udna&type=Date)](https://star-history.com/#w3c-udna/udna&Date)

**Universal DID-Native Addressing is more than a protocol—it's a foundation for a more secure, private, and equitable digital future.**

[![Join W3C Group](https://img.shields.io/badge/Join%20the%20Revolution-Universal%20DID--Native%20Addressing-0066cc?style=for-the-badge&logo=rocket&logoColor=white)](https://www.w3.org/community/udna/)

</div>
```

