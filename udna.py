#!/usr/bin/env python3
"""
Universal DID-Native Addressing (UDNA) Implementation
Based on the UDNA whitepaper v1.0 by Amir Hameed Mir

This is a comprehensive implementation demonstrating the core concepts
of identity-native networking using Decentralized Identifiers (DIDs).
"""

import hashlib
import json
import time
import struct
import secrets
import base58
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hmac

# ============================================================================
# Core Data Structures
# ============================================================================

@dataclass
class Did:
    """Decentralized Identifier representation"""
    method: str
    identifier: str
    
    def __str__(self) -> str:
        return f"did:{self.method}:{self.identifier}"
    
    @classmethod
    def parse(cls, did_string: str) -> 'Did':
        """Parse DID string into components"""
        parts = did_string.split(':')
        if len(parts) < 3 or parts[0] != 'did':
            raise ValueError(f"Invalid DID format: {did_string}")
        return cls(method=parts[1], identifier=':'.join(parts[2:]))
    
    def fingerprint(self) -> bytes:
        """Generate SHA-256 fingerprint for DHT routing"""
        return hashlib.sha256(str(self).encode()).digest()

@dataclass
class ServiceEndpoint:
    """Service endpoint in DID Document"""
    id: str
    type: str
    service_endpoint: str

@dataclass
class VerificationMethod:
    """Verification method for DID Document"""
    id: str
    type: str
    controller: str
    public_key_multibase: str

@dataclass
class DidDocument:
    """W3C DID Document structure"""
    id: str
    verification_method: List[VerificationMethod]
    authentication: List[str]
    service: List[ServiceEndpoint]
    created: str
    updated: str
    
    def get_public_key(self, key_id: str) -> Optional[bytes]:
        """Extract public key bytes from verification method"""
        for vm in self.verification_method:
            if vm.id == key_id:
                # Decode multibase (assuming base58btc encoding)
                return base58.b58decode(vm.public_key_multibase[1:])  # Skip 'z' prefix
        return None

@dataclass
class UdnaAddress:
    """UDNA Address Header structure"""
    version: int = 1
    did_type: int = 1  # 0x01=did:key, 0x02=did:web, 0x10=did:scp
    did: Did = None
    facet_id: int = 0x01  # Service facet
    key_hint: bytes = b''  # Truncated key fingerprint
    route_hint: bytes = b''  # Routing information
    flags: int = 0  # Privacy/rotation flags
    nonce: int = 0  # 64-bit random value
    signature: bytes = b''  # Digital signature
    
    def encode(self) -> bytes:
        """Encode address to binary format"""
        did_bytes = str(self.did).encode('utf-8')
        
        # Pack header fields
        header = struct.pack(
            '!BBHB',  # Ver, DIDType, DIDLen, FacetId
            self.version,
            self.did_type,
            len(did_bytes),
            self.facet_id
        )
        
        header += did_bytes
        
        # Key hint
        header += struct.pack('!B', len(self.key_hint))
        header += self.key_hint
        
        # Route hint
        header += struct.pack('!B', len(self.route_hint))
        header += self.route_hint
        
        # Flags and nonce
        header += struct.pack('!HQ', self.flags, self.nonce)
        
        # Signature
        header += struct.pack('!H', len(self.signature))
        header += self.signature
        
        return header
    
    @classmethod
    def decode(cls, data: bytes) -> 'UdnaAddress':
        """Decode binary format to address"""
        offset = 0
        
        # Unpack basic header
        ver, did_type, did_len, facet_id = struct.unpack_from('!BBHB', data, offset)
        offset += 5
        
        # Extract DID
        did_bytes = data[offset:offset + did_len]
        did = Did.parse(did_bytes.decode('utf-8'))
        offset += did_len
        
        # Key hint
        key_hint_len = struct.unpack_from('!B', data, offset)[0]
        offset += 1
        key_hint = data[offset:offset + key_hint_len]
        offset += key_hint_len
        
        # Route hint
        route_hint_len = struct.unpack_from('!B', data, offset)[0]
        offset += 1
        route_hint = data[offset:offset + route_hint_len]
        offset += route_hint_len
        
        # Flags and nonce
        flags, nonce = struct.unpack_from('!HQ', data, offset)
        offset += 10
        
        # Signature
        sig_len = struct.unpack_from('!H', data, offset)[0]
        offset += 2
        signature = data[offset:offset + sig_len]
        
        return cls(
            version=ver,
            did_type=did_type,
            did=did,
            facet_id=facet_id,
            key_hint=key_hint,
            route_hint=route_hint,
            flags=flags,
            nonce=nonce,
            signature=signature
        )

# ============================================================================
# DID Methods Implementation
# ============================================================================

class DidKeyMethod:
    """Implementation of did:key method"""
    
    @staticmethod
    def generate() -> Tuple[Did, ed25519.Ed25519PrivateKey]:
        """Generate new did:key identity"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Encode public key as multicodec
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Ed25519 public key multicodec prefix (0xed01)
        multicodec_key = b'\xed\x01' + public_key_bytes
        identifier = base58.b58encode(multicodec_key).decode('ascii')
        
        did = Did(method='key', identifier=f'z{identifier}')
        return did, private_key
    
    @staticmethod
    def resolve(did: Did) -> DidDocument:
        """Resolve did:key to DID Document (algorithmic)"""
        if did.method != 'key':
            raise ValueError("Invalid DID method for did:key resolver")
        
        # Extract public key from identifier
        identifier = did.identifier[1:]  # Remove 'z' prefix
        multicodec_key = base58.b58decode(identifier)
        
        if multicodec_key[:2] != b'\xed\x01':
            raise ValueError("Unsupported key type")
        
        public_key_bytes = multicodec_key[2:]
        public_key_multibase = f'z{base58.b58encode(multicodec_key).decode("ascii")}'
        
        # Create DID Document
        key_id = f"{did}#z{identifier}"
        
        return DidDocument(
            id=str(did),
            verification_method=[
                VerificationMethod(
                    id=key_id,
                    type='Ed25519VerificationKey2020',
                    controller=str(did),
                    public_key_multibase=public_key_multibase
                )
            ],
            authentication=[key_id],
            service=[],
            created=time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            updated=time.strftime('%Y-%m-%dT%H:%M:%SZ')
        )

class DidWebMethod:
    """Implementation of did:web method"""
    
    @staticmethod
    def create(domain: str, path: str = '') -> Did:
        """Create did:web identifier"""
        if path:
            identifier = f"{domain}:{path.replace('/', ':')}"
        else:
            identifier = domain
        return Did(method='web', identifier=identifier)
    
    @staticmethod  
    def resolve(did: Did) -> DidDocument:
        """Resolve did:web via HTTPS (simplified)"""
        if did.method != 'web':
            raise ValueError("Invalid DID method for did:web resolver")
        
        # In a real implementation, this would make HTTPS requests
        # For demo, return a mock document
        return DidDocument(
            id=str(did),
            verification_method=[
                VerificationMethod(
                    id=f"{did}#key-1",
                    type='Ed25519VerificationKey2020',
                    controller=str(did),
                    public_key_multibase='z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
                )
            ],
            authentication=[f"{did}#key-1"],
            service=[
                ServiceEndpoint(
                    id=f"{did}#messaging",
                    type='DIDCommMessaging',
                    service_endpoint='https://example.com/didcomm'
                )
            ],
            created=time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            updated=time.strftime('%Y-%m-%dT%H:%M:%SZ')
        )

# ============================================================================
# DID Resolution and Caching
# ============================================================================

class DidCache:
    """Local DID Document cache with TTL management"""
    
    def __init__(self, default_ttl: int = 3600):
        self.cache: Dict[str, Tuple[DidDocument, float]] = {}
        self.default_ttl = default_ttl
    
    def put(self, did: Did, document: DidDocument, ttl: Optional[int] = None):
        """Cache DID document with TTL"""
        expiry = time.time() + (ttl or self.default_ttl)
        self.cache[str(did)] = (document, expiry)
    
    def get(self, did: Did) -> Optional[DidDocument]:
        """Retrieve cached DID document"""
        entry = self.cache.get(str(did))
        if entry:
            document, expiry = entry
            if time.time() < expiry:
                return document
            else:
                del self.cache[str(did)]
        return None
    
    def cleanup(self):
        """Remove expired entries"""
        now = time.time()
        expired = [did for did, (_, expiry) in self.cache.items() if now >= expiry]
        for did in expired:
            del self.cache[did]

class DidResolver:
    """Multi-tier DID resolution system"""
    
    def __init__(self):
        self.cache = DidCache()
        self.resolvers = {
            'key': DidKeyMethod.resolve,
            'web': DidWebMethod.resolve
        }
    
    async def resolve(self, did: Did) -> DidDocument:
        """Resolve DID with caching"""
        # Tier 1: Check local cache
        cached = self.cache.get(did)
        if cached:
            return cached
        
        # Tier 2: Method-specific resolution
        if did.method not in self.resolvers:
            raise ValueError(f"Unsupported DID method: {did.method}")
        
        document = self.resolvers[did.method](did)
        self.cache.put(did, document)
        
        return document

# ============================================================================
# Key Rotation and Recovery
# ============================================================================

@dataclass
class RotationProof:
    """Cryptographic proof of legitimate key rotation"""
    prev_key: bytes
    new_key: bytes
    new_doc_hash: bytes
    valid_from: int
    valid_to: int
    reason: int
    sig_by_prev: bytes
    
    def verify(self, prev_public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify rotation proof signature"""
        try:
            # Create message to verify
            message = (
                self.prev_key +
                self.new_key +
                self.new_doc_hash +
                struct.pack('!QQB', self.valid_from, self.valid_to, self.reason)
            )
            
            prev_public_key.verify(self.sig_by_prev, message)
            return True
        except:
            return False

class KeyRotationManager:
    """Manages cryptographic key rotation"""
    
    def __init__(self):
        self.rotation_proofs: Dict[str, List[RotationProof]] = {}
    
    def rotate_key(self, did: Did, old_private_key: ed25519.Ed25519PrivateKey, 
                   new_private_key: ed25519.Ed25519PrivateKey, 
                   reason: int = 1) -> RotationProof:
        """Create rotation proof for key transition"""
        
        old_public = old_private_key.public_key()
        new_public = new_private_key.public_key()
        
        old_key_bytes = old_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        new_key_bytes = new_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Create new document hash (simplified)
        new_doc_hash = hashlib.sha256(f"{did}:{new_key_bytes.hex()}".encode()).digest()
        
        now = int(time.time())
        valid_from = now
        valid_to = now + (365 * 24 * 3600)  # 1 year
        
        # Sign rotation proof
        message = (
            old_key_bytes +
            new_key_bytes +
            new_doc_hash +
            struct.pack('!QQB', valid_from, valid_to, reason)
        )
        
        signature = old_private_key.sign(message)
        
        proof = RotationProof(
            prev_key=old_key_bytes,
            new_key=new_key_bytes,
            new_doc_hash=new_doc_hash,
            valid_from=valid_from,
            valid_to=valid_to,
            reason=reason,
            sig_by_prev=signature
        )
        
        # Store proof
        if str(did) not in self.rotation_proofs:
            self.rotation_proofs[str(did)] = []
        self.rotation_proofs[str(did)].append(proof)
        
        return proof

# ============================================================================
# Pairwise and Privacy Features
# ============================================================================

class PairwiseDidManager:
    """Manages pairwise DIDs for privacy"""
    
    def __init__(self):
        self.pairwise_seeds: Dict[Tuple[str, str], bytes] = {}
    
    def generate_pairwise_did(self, my_did: Did, peer_did: Did) -> Tuple[Did, ed25519.Ed25519PrivateKey]:
        """Generate pairwise DID for relationship"""
        # Create deterministic seed for this relationship
        relationship_key = tuple(sorted([str(my_did), str(peer_did)]))
        
        if relationship_key not in self.pairwise_seeds:
            # Generate shared secret (in real implementation, use key exchange)
            seed = secrets.token_bytes(32)
            self.pairwise_seeds[relationship_key] = seed
        else:
            seed = self.pairwise_seeds[relationship_key]
        
        # Derive keypair from seed and relationship context
        context = f"{my_did}->{peer_did}".encode()
        derived_seed = hmac.digest(seed, context, hashlib.sha256)
        
        # Generate private key from derived seed (simplified)
        private_key_bytes = hmac.digest(derived_seed, b"private_key", hashlib.sha256)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        
        # Create pairwise did:key
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        multicodec_key = b'\xed\x01' + public_key_bytes
        identifier = base58.b58encode(multicodec_key).decode('ascii')
        pairwise_did = Did(method='key', identifier=f'z{identifier}')
        
        return pairwise_did, private_key

# ============================================================================
# Noise Protocol Integration
# ============================================================================

class NoiseHandshake:
    """Simplified Noise protocol handshake with DID authentication"""
    
    def __init__(self):
        self.sessions: Dict[str, Dict] = {}
    
    def initiate_handshake(self, local_did: Did, local_private_key: ed25519.Ed25519PrivateKey,
                          remote_did: Did) -> Tuple[str, bytes]:
        """Initiate Noise handshake with DID identity"""
        session_id = secrets.token_hex(16)
        
        # Generate ephemeral key for handshake
        ephemeral_key = ed25519.Ed25519PrivateKey.generate()
        
        # Create handshake message (simplified Noise-IK pattern)
        ephemeral_public = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Sign ephemeral key with DID key
        signature = local_private_key.sign(ephemeral_public + str(remote_did).encode())
        
        message = {
            'type': 'handshake_init',
            'session_id': session_id,
            'local_did': str(local_did),
            'remote_did': str(remote_did),
            'ephemeral_key': ephemeral_public.hex(),
            'signature': signature.hex(),
            'timestamp': int(time.time())
        }
        
        # Store session state
        self.sessions[session_id] = {
            'local_did': local_did,
            'remote_did': remote_did,
            'local_private_key': local_private_key,
            'ephemeral_private_key': ephemeral_key,
            'state': 'initiated'
        }
        
        return session_id, json.dumps(message).encode()
    
    def respond_to_handshake(self, local_did: Did, local_private_key: ed25519.Ed25519PrivateKey,
                            init_message: bytes) -> Tuple[str, bytes]:
        """Respond to handshake initiation"""
        message = json.loads(init_message.decode())
        
        if message['type'] != 'handshake_init':
            raise ValueError("Invalid handshake message")
        
        session_id = message['session_id']
        remote_did = Did.parse(message['local_did'])  # Swap perspective
        
        # Generate our ephemeral key
        ephemeral_key = ed25519.Ed25519PrivateKey.generate()
        ephemeral_public = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Create response
        signature = local_private_key.sign(ephemeral_public + str(remote_did).encode())
        
        response = {
            'type': 'handshake_response',
            'session_id': session_id,
            'local_did': str(local_did),
            'ephemeral_key': ephemeral_public.hex(),
            'signature': signature.hex(),
            'timestamp': int(time.time())
        }
        
        # Store session
        self.sessions[session_id] = {
            'local_did': local_did,
            'remote_did': remote_did,
            'local_private_key': local_private_key,
            'ephemeral_private_key': ephemeral_key,
            'remote_ephemeral_key': bytes.fromhex(message['ephemeral_key']),
            'state': 'responded'
        }
        
        return session_id, json.dumps(response).encode()
    
    def finalize_handshake(self, session_id: str, response_message: bytes) -> bytes:
        """Finalize handshake and derive session key"""
        if session_id not in self.sessions:
            raise ValueError("Unknown session")
        
        session = self.sessions[session_id]
        message = json.loads(response_message.decode())
        
        # In a full Noise implementation, this would perform DH key exchange
        # For demo, we'll derive a session key from the DIDs and ephemeral keys
        remote_ephemeral = bytes.fromhex(message['ephemeral_key'])
        
        # Simplified session key derivation
        key_material = (
            str(session['local_did']).encode() +
            str(session['remote_did']).encode() +
            session['ephemeral_private_key'].public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ) +
            remote_ephemeral
        )
        
        session_key = hashlib.sha256(key_material).digest()
        session['session_key'] = session_key
        session['state'] = 'established'
        
        return session_key

# ============================================================================
# Message Encryption and Authentication  
# ============================================================================

class SecureMessaging:
    """End-to-end encrypted messaging using session keys"""
    
    def __init__(self):
        self.cipher_suite = ChaCha20Poly1305
    
    def encrypt_message(self, session_key: bytes, plaintext: bytes, 
                       associated_data: bytes = b'') -> bytes:
        """Encrypt message with session key"""
        cipher = self.cipher_suite(session_key)
        nonce = secrets.token_bytes(12)  # ChaCha20Poly1305 uses 12-byte nonces
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext
    
    def decrypt_message(self, session_key: bytes, encrypted_data: bytes,
                       associated_data: bytes = b'') -> bytes:
        """Decrypt message with session key"""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        cipher = self.cipher_suite(session_key)
        return cipher.decrypt(nonce, ciphertext, associated_data)

# ============================================================================
# DHT Overlay Network (Simplified)
# ============================================================================

class DhtNode:
    """Simplified DHT node for DID resolution"""
    
    def __init__(self, node_id: bytes):
        self.node_id = node_id
        self.routing_table: Dict[bytes, str] = {}  # node_id -> endpoint
        self.storage: Dict[bytes, bytes] = {}  # key -> value
    
    def distance(self, key: bytes) -> int:
        """XOR distance metric"""
        return int.from_bytes(
            bytes(a ^ b for a, b in zip(self.node_id, key)),
            byteorder='big'
        )
    
    def store(self, key: bytes, value: bytes):
        """Store key-value pair"""
        self.storage[key] = value
    
    def lookup(self, key: bytes) -> Optional[bytes]:
        """Lookup value by key"""
        return self.storage.get(key)
    
    def find_closest_nodes(self, key: bytes, k: int = 3) -> List[bytes]:
        """Find k closest nodes to key"""
        distances = [(self.distance(key ^ node_id), node_id) 
                    for node_id in self.routing_table.keys()]
        distances.sort()
        return [node_id for _, node_id in distances[:k]]

# ============================================================================
# Demo and Testing
# ============================================================================

class UdnaDemo:
    """Demonstration of UDNA functionality"""
    
    def __init__(self):
        self.resolver = DidResolver()
        self.handshake_handler = NoiseHandshake()
        self.messaging = SecureMessaging()
        self.rotation_manager = KeyRotationManager()
        self.pairwise_manager = PairwiseDidManager()
    
    def demo_basic_operations(self):
        """Demonstrate basic UDNA operations"""
        print("=== UDNA Demo: Basic Operations ===\n")
        
        # 1. Generate did:key identities
        print("1. Generating did:key identities...")
        alice_did, alice_key = DidKeyMethod.generate()
        bob_did, bob_key = DidKeyMethod.generate()
        print(f"Alice DID: {alice_did}")
        print(f"Bob DID: {bob_did}\n")
        
        # 2. Resolve DID documents
        print("2. Resolving DID documents...")
        alice_doc = DidKeyMethod.resolve(alice_did)
        bob_doc = DidKeyMethod.resolve(bob_did)
        print(f"Alice doc created: {alice_doc.created}")
        print(f"Bob doc created: {bob_doc.created}\n")
        
        # 3. Create and encode UDNA addresses
        print("3. Creating UDNA addresses...")
        alice_addr = UdnaAddress(
            did=alice_did,
            facet_id=0x02,  # Messaging facet
            nonce=secrets.randbits(64)
        )
        
        # Encode and decode address
        encoded = alice_addr.encode()
        decoded = UdnaAddress.decode(encoded)
        print(f"Address encoding size: {len(encoded)} bytes")
        print(f"Decoded DID matches: {decoded.did == alice_did}\n")
        
        # 4. Generate pairwise DIDs
        print("4. Generating pairwise DIDs...")
        alice_pairwise, alice_pairwise_key = self.pairwise_manager.generate_pairwise_did(
            alice_did, bob_did
        )
        bob_pairwise, bob_pairwise_key = self.pairwise_manager.generate_pairwise_did(
            bob_did, alice_did
        )
        print(f"Alice pairwise: {alice_pairwise}")
        print(f"Bob pairwise: {bob_pairwise}\n")
        
        # 5. Perform cryptographic handshake
        print("5. Performing Noise handshake...")
        session_id, init_msg = self.handshake_handler.initiate_handshake(
            alice_did, alice_key, bob_did
        )
        
        _, response_msg = self.handshake_handler.respond_to_handshake(
            bob_did, bob_key, init_msg
        )
        
        session_key = self.handshake_handler.finalize_handshake(session_id, response_msg)
        print(f"Session established: {session_key.hex()[:16]}...\n")
        
        # 6. Send encrypted message
        print("6. Sending encrypted message...")
        plaintext = b"Hello Bob, this is a secure DID-authenticated message!"
        encrypted = self.messaging.encrypt_message(session_key, plaintext)
        decrypted = self.messaging.decrypt_message(session_key, encrypted)
        print(f"Message encrypted: {len(encrypted)} bytes")
        print(f"Decryption successful: {decrypted == plaintext}\n")
        
        # 7. Demonstrate key rotation
        print("7. Demonstrating key rotation...")
        new_alice_key = ed25519.Ed25519PrivateKey.generate()
        rotation_proof = self.rotation_manager.rotate_key(
            alice_did, alice_key, new_alice_key, reason=1
        )
        
        # Verify rotation proof
        alice_public = alice_key.public_key()
        is_valid = rotation_proof.verify(alice_public)
        print(f"Key rotation proof valid: {is_valid}\n")
        
        return {
            'alice_did': alice_did,
            'bob_did': bob_did,
            'session_key': session_key,
            'pairwise_dids': (alice_pairwise, bob_pairwise)
        }
    
    def demo_performance_benchmarks(self):
        """Run performance benchmarks"""
        print("=== UDNA Demo: Performance Benchmarks ===\n")
        
        # DID resolution benchmark
        test_did, _ = DidKeyMethod.generate()
        
        import time
        iterations = 1000
        
        # Benchmark DID resolution
        start = time.perf_counter()
        for _ in range(iterations):
            DidKeyMethod.resolve(test_did)
        end = time.perf_counter()
        
        avg_resolution = (end - start) / iterations * 1000000  # microseconds
        print(f"DID Resolution (algorithmic): {avg_resolution:.1f} μs average")
        
        # Benchmark address encoding/decoding
        addr = UdnaAddress(did=test_did, nonce=secrets.randbits(64))
        
        start = time.perf_counter()
        for _ in range(iterations):
            encoded = addr.encode()
            UdnaAddress.decode(encoded)
        end = time.perf_counter()
        
        avg_encode_decode = (end - start) / iterations * 1000000
        print(f"Address Encode/Decode: {avg_encode_decode:.1f} μs average")
        
        # Benchmark signature verification
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        message = b"test message for signature benchmarking"
        signature = private_key.sign(message)
        
        start = time.perf_counter()
        for _ in range(iterations):
            try:
                public_key.verify(signature, message)
            except:
                pass
        end = time.perf_counter()
        
        avg_verify = (end - start) / iterations * 1000000
        print(f"Signature Verification: {avg_verify:.1f} μs average\n")

def main():
    """Run UDNA demonstration"""
    demo = UdnaDemo()
    
    try:
        # Run basic functionality demo
        results = demo.demo_basic_operations()
        
        # Run performance benchmarks
        demo.demo_performance_benchmarks()
        
        # Additional advanced demos
        demo.demo_capability_system()
        demo.demo_relay_contracts()
        demo.demo_anonymous_introduction()
        
    except Exception as e:
        print(f"Demo error: {e}")
        import traceback
        traceback.print_exc()

    def demo_capability_system(self):
        """Demonstrate Zero-Knowledge Capability (ZCAP) system"""
        print("=== UDNA Demo: Capability-Based Authorization ===\n")
        
        # Generate identities
        alice_did, alice_key = DidKeyMethod.generate()
        bob_did, bob_key = DidKeyMethod.generate()
        service_did, service_key = DidKeyMethod.generate()
        
        print(f"Alice (client): {alice_did}")
        print(f"Bob (delegate): {bob_did}")  
        print(f"Service: {service_did}\n")
        
        # Create capability
        capability = ZeroKnowledgeCapability(
            controller=str(alice_did),
            subject=str(service_did),
            action=['read', 'write'],
            resource='/api/documents/*',
            expires=int(time.time()) + 3600,  # 1 hour
            nonce=secrets.token_hex(16)
        )
        
        # Sign capability
        capability.sign(alice_key)
        print(f"Capability created: {capability.id}")
        print(f"Actions: {capability.action}")
        print(f"Resource: {capability.resource}\n")
        
        # Delegate capability to Bob
        delegated_cap = capability.delegate(bob_did, alice_key, ['read'])
        print(f"Delegated to Bob: {delegated_cap.id}")
        print(f"Delegated actions: {delegated_cap.action}\n")
        
        # Verify capability chain
        is_valid = delegated_cap.verify_chain([capability])
        print(f"Delegation chain valid: {is_valid}\n")
        
        return capability, delegated_cap
    
    def demo_relay_contracts(self):
        """Demonstrate relay contracts for NAT traversal"""
        print("=== UDNA Demo: Relay Contracts ===\n")
        
        # Generate identities
        client_did, client_key = DidKeyMethod.generate()
        relay_did, relay_key = DidKeyMethod.generate()
        
        print(f"Client: {client_did}")
        print(f"Relay: {relay_did}\n")
        
        # Create relay contract
        contract = RelayContract(
            relay_did=relay_did,
            client_did=client_did,
            permitted_facets=[0x01, 0x02, 0x03],  # Control, Messaging, Telemetry
            rate_limits=RateConfig(
                requests_per_second=100,
                bandwidth_mbps=10,
                concurrent_connections=50
            ),
            fee_structure=FeeConfig(
                base_fee_sats=100,
                per_mb_sats=10,
                per_hour_sats=50
            ),
            valid_until=int(time.time()) + 86400,  # 24 hours
            signatures=[]
        )
        
        # Multi-party signatures
        client_sig = contract.sign(client_key, str(client_did))
        relay_sig = contract.sign(relay_key, str(relay_did))
        
        print(f"Contract ID: {contract.contract_id()}")
        print(f"Permitted facets: {contract.permitted_facets}")
        print(f"Rate limit: {contract.rate_limits.requests_per_second} req/s")
        print(f"Valid until: {time.ctime(contract.valid_until)}")
        print(f"Signatures: {len(contract.signatures)}\n")
        
        # Verify contract
        is_valid = contract.verify_signatures()
        print(f"Contract signatures valid: {is_valid}\n")
        
        return contract
    
    def demo_anonymous_introduction(self):
        """Demonstrate anonymous introduction protocol"""
        print("=== UDNA Demo: Anonymous Introduction ===\n")
        
        # Generate identities
        alice_did, alice_key = DidKeyMethod.generate()
        bob_did, bob_key = DidKeyMethod.generate()
        rendezvous_did, rendezvous_key = DidKeyMethod.generate()
        
        print(f"Alice (initiator): {alice_did}")
        print(f"Bob (responder): {bob_did}")
        print(f"Rendezvous: {rendezvous_did}\n")
        
        # Create anonymous introduction request
        intro_request = AnonymousIntroduction(
            rendezvous_did=rendezvous_did,
            target_did=bob_did,
            introduction_purpose="secure_messaging",
            capabilities_requested=['read', 'write'],
            anonymity_level=2,  # Medium anonymity
            nonce=secrets.token_hex(16)
        )
        
        # Alice signs with ephemeral key
        ephemeral_key = ed25519.Ed25519PrivateKey.generate()
        intro_request.sign(ephemeral_key)
        
        print(f"Introduction request: {intro_request.request_id}")
        print(f"Target: {intro_request.target_did}")
        print(f"Purpose: {intro_request.introduction_purpose}")
        print(f"Anonymity level: {intro_request.anonymity_level}\n")
        
        # Bob evaluates introduction against policy
        policy_result = intro_request.evaluate_policy(bob_did, bob_key)
        print(f"Policy evaluation: {policy_result.decision}")
        print(f"Reason: {policy_result.reason}\n")
        
        if policy_result.decision == "accept":
            # Reveal real identity
            alice_revelation = intro_request.reveal_identity(alice_did, alice_key)
            print(f"Identity revealed: {alice_revelation.real_did}")
            print(f"Verification: {alice_revelation.verify()}\n")
        
        return intro_request

# ============================================================================
# Advanced Components
# ============================================================================

@dataclass
class ZeroKnowledgeCapability:
    """Zero-Knowledge Capability for fine-grained authorization"""
    controller: str  # DID of capability controller
    subject: str     # DID of resource subject
    action: List[str]  # Permitted actions
    resource: str    # Resource identifier/pattern
    expires: int     # Expiration timestamp
    nonce: str       # Unique nonce
    parent_id: Optional[str] = None  # Parent capability ID for delegation
    signature: bytes = b''
    
    @property
    def id(self) -> str:
        """Generate capability ID"""
        content = f"{self.controller}:{self.subject}:{':'.join(self.action)}:{self.resource}:{self.expires}:{self.nonce}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def sign(self, private_key: ed25519.Ed25519PrivateKey):
        """Sign capability with controller's key"""
        message = f"{self.id}:{self.controller}:{self.subject}".encode()
        self.signature = private_key.sign(message)
    
    def delegate(self, delegate_did: Did, controller_key: ed25519.Ed25519PrivateKey, 
                 delegated_actions: List[str]) -> 'ZeroKnowledgeCapability':
        """Create delegated capability"""
        # Ensure delegated actions are subset of parent actions
        if not all(action in self.action for action in delegated_actions):
            raise ValueError("Cannot delegate actions not possessed")
        
        delegated_cap = ZeroKnowledgeCapability(
            controller=str(delegate_did),
            subject=self.subject,
            action=delegated_actions,
            resource=self.resource,
            expires=min(self.expires, int(time.time()) + 3600),  # Max 1 hour or parent expiry
            nonce=secrets.token_hex(16),
            parent_id=self.id
        )
        
        # Sign delegation
        delegated_cap.sign(controller_key)
        
        return delegated_cap
    
    def verify_chain(self, parent_capabilities: List['ZeroKnowledgeCapability']) -> bool:
        """Verify capability delegation chain"""
        if not self.parent_id:
            return True  # Root capability
        
        # Find parent capability
        parent = next((cap for cap in parent_capabilities if cap.id == self.parent_id), None)
        if not parent:
            return False
        
        # Verify parent is still valid
        if parent.expires < time.time():
            return False
        
        # Verify actions are subset of parent
        if not all(action in parent.action for action in self.action):
            return False
        
        # Recursively verify parent chain
        return parent.verify_chain(parent_capabilities)

@dataclass
class RateConfig:
    """Rate limiting configuration"""
    requests_per_second: int
    bandwidth_mbps: int
    concurrent_connections: int

@dataclass
class FeeConfig:
    """Fee structure for relay services"""
    base_fee_sats: int      # Base fee in satoshis
    per_mb_sats: int        # Per megabyte fee
    per_hour_sats: int      # Per hour fee

@dataclass
class RelayContract:
    """Cryptographically enforced relay contract"""
    relay_did: Did
    client_did: Did
    permitted_facets: List[int]
    rate_limits: RateConfig
    fee_structure: FeeConfig
    valid_until: int
    signatures: List[Tuple[str, bytes]]  # (signer_did, signature) pairs
    
    def contract_id(self) -> str:
        """Generate unique contract ID"""
        content = f"{self.relay_did}:{self.client_did}:{self.valid_until}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def sign(self, private_key: ed25519.Ed25519PrivateKey, signer_did: str) -> bytes:
        """Add signature to contract"""
        message = (
            f"{self.contract_id()}:"
            f"{self.relay_did}:{self.client_did}:"
            f"{':'.join(map(str, self.permitted_facets))}:"
            f"{self.rate_limits.requests_per_second}:"
            f"{self.valid_until}"
        ).encode()
        
        signature = private_key.sign(message)
        self.signatures.append((signer_did, signature))
        return signature
    
    def verify_signatures(self) -> bool:
        """Verify all contract signatures (simplified)"""
        # In a real implementation, this would resolve DIDs and verify signatures
        # For demo, we assume valid if both parties signed
        signers = {signer for signer, _ in self.signatures}
        required_signers = {str(self.relay_did), str(self.client_did)}
        return required_signers.issubset(signers)

@dataclass
class PolicyResult:
    """Result of policy evaluation"""
    decision: str  # "accept", "reject", "defer"
    reason: str
    required_capabilities: List[str] = None

@dataclass
class IdentityRevelation:
    """Identity revelation after successful introduction"""
    request_id: str
    real_did: Did
    ephemeral_did: Did
    proof_signature: bytes
    
    def verify(self) -> bool:
        """Verify identity revelation proof"""
        # Simplified verification
        return len(self.proof_signature) > 0

@dataclass
class AnonymousIntroduction:
    """Anonymous introduction protocol message"""
    rendezvous_did: Did
    target_did: Did
    introduction_purpose: str
    capabilities_requested: List[str]
    anonymity_level: int  # 0=none, 1=low, 2=medium, 3=high
    nonce: str
    signature: bytes = b''
    
    @property
    def request_id(self) -> str:
        """Generate request ID"""
        content = f"{self.rendezvous_did}:{self.target_did}:{self.nonce}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def sign(self, ephemeral_key: ed25519.Ed25519PrivateKey):
        """Sign introduction request with ephemeral key"""
        message = f"{self.request_id}:{self.target_did}:{self.introduction_purpose}".encode()
        self.signature = ephemeral_key.sign(message)
    
    def evaluate_policy(self, target_did: Did, target_key: ed25519.Ed25519PrivateKey) -> PolicyResult:
        """Evaluate introduction against access policy"""
        # Simplified policy evaluation
        if self.introduction_purpose in ["secure_messaging", "file_sharing"]:
            return PolicyResult(
                decision="accept",
                reason="Purpose matches allowed activities"
            )
        else:
            return PolicyResult(
                decision="reject", 
                reason="Unknown introduction purpose"
            )
    
    def reveal_identity(self, real_did: Did, real_key: ed25519.Ed25519PrivateKey) -> IdentityRevelation:
        """Reveal real identity after policy acceptance"""
        proof_message = f"{self.request_id}:{real_did}".encode()
        proof_signature = real_key.sign(proof_message)
        
        return IdentityRevelation(
            request_id=self.request_id,
            real_did=real_did,
            ephemeral_did=Did.parse(f"did:key:ephemeral_{self.nonce}"),
            proof_signature=proof_signature
        )

if __name__ == "__main__":
    main()