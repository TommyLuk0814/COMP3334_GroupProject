import time
import base64
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


class CryptoManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.session_keys = {}
        self.pending_initiator_keys: Dict[int, Tuple[str, str, X25519PrivateKey]] = {}
        self.finalized_handshakes = set()
        self.identity_dir = Path(__file__).resolve().parent / ".identity"
        self.private_key_path = self.identity_dir / "ed25519_private.pem"
        self.public_key_path = self.identity_dir / "ed25519_public.pem"
        self._load_or_create_identity_keypair()

    def _load_or_create_identity_keypair(self):
        self.identity_dir.mkdir(parents=True, exist_ok=True)
        if self.private_key_path.exists() and self.public_key_path.exists():
            private_bytes = self.private_key_path.read_bytes()
            public_bytes = self.public_key_path.read_bytes()
            self.private_key = serialization.load_pem_private_key(private_bytes, password=None)
            self.public_key = serialization.load_pem_public_key(public_bytes)
            return

        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.private_key_path.write_bytes(private_pem)
        self.public_key_path.write_bytes(public_pem)

    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def _identity_private_key(self) -> Ed25519PrivateKey:
        if not isinstance(self.private_key, Ed25519PrivateKey):
            raise ValueError("Identity key is not Ed25519 private key")
        return self.private_key

    def _identity_public_key_from_pem(self, public_key_pem: str) -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Peer identity key is not Ed25519 public key")
        return key

    def _derive_shared_key(self, shared_secret: bytes) -> str:
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"secure-im-r7-session",
        ).derive(shared_secret)
        return base64.b64encode(key).decode("utf-8")

    def _handshake_payload_init(
        self,
        initiator_username: str,
        initiator_device_id: str,
        recipient_username: str,
        recipient_device_id: str,
        initiator_ephemeral_pub: str,
    ) -> bytes:
        payload = "|".join(
            [
                "R7_INIT",
                initiator_username,
                initiator_device_id,
                recipient_username,
                recipient_device_id,
                initiator_ephemeral_pub,
            ]
        )
        return payload.encode("utf-8")

    def _handshake_payload_response(
        self,
        handshake_id: int,
        initiator_username: str,
        initiator_device_id: str,
        recipient_username: str,
        recipient_device_id: str,
        initiator_ephemeral_pub: str,
        responder_ephemeral_pub: str,
    ) -> bytes:
        payload = "|".join(
            [
                "R7_RESP",
                str(handshake_id),
                initiator_username,
                initiator_device_id,
                recipient_username,
                recipient_device_id,
                initiator_ephemeral_pub,
                responder_ephemeral_pub,
            ]
        )
        return payload.encode("utf-8")

    def create_initiator_handshake(
        self,
        initiator_username: str,
        initiator_device_id: str,
        recipient_username: str,
        recipient_device_id: str,
    ) -> Tuple[str, str, X25519PrivateKey]:
        eph_private = X25519PrivateKey.generate()
        eph_public = eph_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        eph_pub_b64 = base64.b64encode(eph_public).decode("utf-8")

        payload = self._handshake_payload_init(
            initiator_username,
            initiator_device_id,
            recipient_username,
            recipient_device_id,
            eph_pub_b64,
        )
        signature = self._identity_private_key().sign(payload)
        signature_b64 = base64.b64encode(signature).decode("utf-8")
        return eph_pub_b64, signature_b64, eph_private

    def remember_initiator_private_key(
        self,
        handshake_id: int,
        recipient_username: str,
        recipient_device_id: str,
        eph_private: X25519PrivateKey,
    ) -> None:
        self.pending_initiator_keys[handshake_id] = (recipient_username, recipient_device_id, eph_private)

    def handle_incoming_handshake(
        self,
        handshake: Dict[str, str],
        my_username: str,
        my_device_id: str,
        initiator_identity_key_pem: str,
    ) -> Tuple[str, str, str]:
        initiator_username = handshake["initiator_username"]
        initiator_device_id = handshake["initiator_device_id"]
        initiator_ephemeral_pub = handshake["initiator_ephemeral_pub"]
        initiator_signature = handshake["initiator_signature"]

        init_payload = self._handshake_payload_init(
            initiator_username,
            initiator_device_id,
            my_username,
            my_device_id,
            initiator_ephemeral_pub,
        )
        initiator_pub = self._identity_public_key_from_pem(initiator_identity_key_pem)
        initiator_pub.verify(base64.b64decode(initiator_signature.encode("utf-8")), init_payload)

        responder_private = X25519PrivateKey.generate()
        responder_pub_raw = responder_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        responder_pub_b64 = base64.b64encode(responder_pub_raw).decode("utf-8")

        response_payload = self._handshake_payload_response(
            int(handshake["id"]),
            initiator_username,
            initiator_device_id,
            my_username,
            my_device_id,
            initiator_ephemeral_pub,
            responder_pub_b64,
        )
        responder_sig_b64 = base64.b64encode(self._identity_private_key().sign(response_payload)).decode("utf-8")

        initiator_eph_pub = X25519PublicKey.from_public_bytes(base64.b64decode(initiator_ephemeral_pub.encode("utf-8")))
        shared_secret = responder_private.exchange(initiator_eph_pub)
        shared_key_b64 = self._derive_shared_key(shared_secret)
        self.session_keys[initiator_username] = {
            "peer_device_id": initiator_device_id,
            "session_key": shared_key_b64,
            "established_by": "responder",
            "handshake_id": int(handshake["id"]),
        }
        return responder_pub_b64, responder_sig_b64, shared_key_b64

    def finalize_initiator_handshake(
        self,
        handshake: Dict[str, str],
        my_username: str,
        my_device_id: str,
        recipient_identity_key_pem: str,
    ) -> Optional[str]:
        handshake_id = int(handshake["id"])
        if handshake_id in self.finalized_handshakes:
            return None

        pending = self.pending_initiator_keys.get(handshake_id)
        if not pending:
            return None

        recipient_username, recipient_device_id, eph_private = pending
        if recipient_username != handshake["recipient_username"]:
            return None

        initiator_ephemeral_pub = handshake["initiator_ephemeral_pub"]
        responder_ephemeral_pub = handshake["responder_ephemeral_pub"]
        responder_signature = handshake["responder_signature"]

        response_payload = self._handshake_payload_response(
            handshake_id,
            my_username,
            my_device_id,
            recipient_username,
            recipient_device_id,
            initiator_ephemeral_pub,
            responder_ephemeral_pub,
        )
        recipient_pub = self._identity_public_key_from_pem(recipient_identity_key_pem)
        recipient_pub.verify(base64.b64decode(responder_signature.encode("utf-8")), response_payload)

        responder_eph_pub = X25519PublicKey.from_public_bytes(base64.b64decode(responder_ephemeral_pub.encode("utf-8")))
        shared_secret = eph_private.exchange(responder_eph_pub)
        shared_key_b64 = self._derive_shared_key(shared_secret)
        self.session_keys[recipient_username] = {
            "peer_device_id": recipient_device_id,
            "session_key": shared_key_b64,
            "established_by": "initiator",
            "handshake_id": handshake_id,
        }
        self.finalized_handshakes.add(handshake_id)
        self.pending_initiator_keys.pop(handshake_id, None)
        return shared_key_b64

    def has_session_with(self, peer_username: str) -> bool:
        return peer_username in self.session_keys

    def load_peer_public_key(self, peer, pem):
        self.session_keys[peer] = {
            "peer_identity_key": Ed25519PublicKey.from_public_bytes(
                serialization.load_pem_public_key(pem.encode("utf-8")).public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
        }

    def encrypt_message(self, peer, message, expiry):
        return {
            "ciphertext": message,
            "nonce": "mock_nonce",
            "timestamp": int(time.time()),
        }

    def decrypt_message(self, sender, ciphertext, nonce, timestamp, expiry):
        return ciphertext, None
