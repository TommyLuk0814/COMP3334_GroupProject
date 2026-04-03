import time
import base64
import json
import os
import uuid
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


class CryptoManager:
    def __init__(self, profile_name="default"):
        self.private_key = None
        self.public_key = None
        self.session_keys = {}
        self.pending_initiator_keys: Dict[int, Tuple[str, str, X25519PrivateKey]] = {}
        self.finalized_handshakes = set()
        self.local_prekeys: Dict[str, Dict[str, str]] = {}
        self.profile_name = self._normalize_profile_name(profile_name)
        self.identity_dir = Path(__file__).resolve().parent / ".identity_profiles" / self.profile_name
        self.private_key_path = self.identity_dir / "ed25519_private.pem"
        self.public_key_path = self.identity_dir / "ed25519_public.pem"
        self.prekey_store_path = self.identity_dir / "prekeys_private.json"
        self._load_or_create_identity_keypair()
        self._load_local_prekeys()

    def _normalize_profile_name(self, profile_name):
        raw = (str(profile_name or "default")).strip().lower()
        sanitized = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in raw)
        return sanitized or "default"

    def _load_local_prekeys(self):
        if not self.prekey_store_path.exists():
            self.local_prekeys = {}
            return
        try:
            data = json.loads(self.prekey_store_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self.local_prekeys = data
            else:
                self.local_prekeys = {}
        except Exception:
            self.local_prekeys = {}

    def _persist_local_prekeys(self):
        self.prekey_store_path.write_text(json.dumps(self.local_prekeys, indent=2), encoding="utf-8")

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

    def _prekey_upload_payload(
        self,
        username: str,
        device_id: str,
        prekey_id: str,
        prekey_public: str,
    ) -> bytes:
        return "|".join([
            "R7_PREKEY",
            username,
            device_id,
            prekey_id,
            prekey_public,
        ]).encode("utf-8")

    def _prekey_init_payload(
        self,
        sender_username: str,
        sender_device_id: str,
        recipient_username: str,
        recipient_device_id: str,
        prekey_id: str,
        sender_ephemeral_pub: str,
    ) -> bytes:
        return "|".join([
            "R7_PREKEY_INIT",
            sender_username,
            sender_device_id,
            recipient_username,
            recipient_device_id,
            prekey_id,
            sender_ephemeral_pub,
        ]).encode("utf-8")

    def generate_prekeys_upload_batch(self, username: str, device_id: str, count: int = 20):
        normalized_user = (username or "").strip().lower()
        normalized_device = (device_id or "").strip()
        if not normalized_user or not normalized_device or count <= 0:
            return []

        upload_entries = []
        for _ in range(count):
            prekey_private = X25519PrivateKey.generate()
            prekey_public_raw = prekey_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            prekey_public = base64.b64encode(prekey_public_raw).decode("utf-8")
            prekey_id = f"pk-{uuid.uuid4().hex}"
            payload = self._prekey_upload_payload(
                username=normalized_user,
                device_id=normalized_device,
                prekey_id=prekey_id,
                prekey_public=prekey_public,
            )
            signature = self._identity_private_key().sign(payload)
            prekey_signature = base64.b64encode(signature).decode("utf-8")

            private_raw = prekey_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.local_prekeys[prekey_id] = {
                "device_id": normalized_device,
                "private": base64.b64encode(private_raw).decode("utf-8"),
                "created_at": str(int(time.time())),
            }
            upload_entries.append(
                {
                    "prekey_id": prekey_id,
                    "prekey_public": prekey_public,
                    "prekey_signature": prekey_signature,
                }
            )

        self._persist_local_prekeys()
        return upload_entries

    def _set_session(
        self,
        peer_username: str,
        peer_device_id: str,
        session_key_b64: str,
        established_by: str,
        bootstrap: Optional[Dict[str, str]] = None,
    ):
        entry = {
            "peer_device_id": peer_device_id,
            "session_key": session_key_b64,
            "established_by": established_by,
        }
        if bootstrap:
            entry["bootstrap"] = dict(bootstrap)
        self.session_keys[peer_username] = entry

    def encrypt_message_with_prekey_bundle(
        self,
        peer_username: str,
        peer_device_id: str,
        my_username: str,
        my_device_id: str,
        peer_identity_key_pem: str,
        prekey_id: str,
        prekey_public: str,
        prekey_signature: str,
        message: str,
        aad_obj: Dict[str, object],
    ) -> Dict[str, object]:
        peer_pub = self._identity_public_key_from_pem(peer_identity_key_pem)
        upload_payload = self._prekey_upload_payload(
            username=peer_username,
            device_id=peer_device_id,
            prekey_id=prekey_id,
            prekey_public=prekey_public,
        )
        peer_pub.verify(base64.b64decode(prekey_signature.encode("utf-8")), upload_payload)

        sender_eph_private = X25519PrivateKey.generate()
        sender_eph_public_raw = sender_eph_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        sender_eph_public = base64.b64encode(sender_eph_public_raw).decode("utf-8")
        init_payload = self._prekey_init_payload(
            sender_username=my_username,
            sender_device_id=my_device_id,
            recipient_username=peer_username,
            recipient_device_id=peer_device_id,
            prekey_id=prekey_id,
            sender_ephemeral_pub=sender_eph_public,
        )
        sender_eph_sig = base64.b64encode(self._identity_private_key().sign(init_payload)).decode("utf-8")

        peer_prekey_pub = X25519PublicKey.from_public_bytes(base64.b64decode(prekey_public.encode("utf-8")))
        shared_secret = sender_eph_private.exchange(peer_prekey_pub)
        session_key_b64 = self._derive_shared_key(shared_secret)
        self._set_session(
            peer_username,
            peer_device_id,
            session_key_b64,
            "prekey-initiator",
            bootstrap={
                "session_mode": "prekey",
                "prekey_id": prekey_id,
                "sender_eph_pub": sender_eph_public,
                "sender_eph_sig": sender_eph_sig,
            },
        )

        aad = dict(aad_obj)
        aad.update(
            {
                "session_mode": "prekey",
                "prekey_id": prekey_id,
                "sender_eph_pub": sender_eph_public,
                "sender_eph_sig": sender_eph_sig,
            }
        )
        encrypted = self.encrypt_message(peer_username, message, aad)
        encrypted["recipient_device_id"] = peer_device_id
        return encrypted

    def establish_session_from_prekey_message(
        self,
        sender_username: str,
        sender_device_id: str,
        my_username: str,
        my_device_id: str,
        sender_identity_key_pem: str,
        aad_obj: Dict[str, object],
    ) -> bool:
        if str(aad_obj.get("session_mode", "")) != "prekey":
            return False
        prekey_id = str(aad_obj.get("prekey_id", ""))
        sender_eph_pub = str(aad_obj.get("sender_eph_pub", ""))
        sender_eph_sig = str(aad_obj.get("sender_eph_sig", ""))
        if not prekey_id or not sender_eph_pub or not sender_eph_sig:
            return False

        local_entry = self.local_prekeys.get(prekey_id)
        if not local_entry:
            return False
        if str(local_entry.get("device_id", "")) != my_device_id:
            return False

        sender_pub = self._identity_public_key_from_pem(sender_identity_key_pem)
        init_payload = self._prekey_init_payload(
            sender_username=sender_username,
            sender_device_id=sender_device_id,
            recipient_username=my_username,
            recipient_device_id=my_device_id,
            prekey_id=prekey_id,
            sender_ephemeral_pub=sender_eph_pub,
        )
        sender_pub.verify(base64.b64decode(sender_eph_sig.encode("utf-8")), init_payload)

        prekey_private_raw = base64.b64decode(str(local_entry.get("private", "")).encode("utf-8"))
        prekey_private = X25519PrivateKey.from_private_bytes(prekey_private_raw)
        sender_eph_public = X25519PublicKey.from_public_bytes(base64.b64decode(sender_eph_pub.encode("utf-8")))
        shared_secret = prekey_private.exchange(sender_eph_public)
        session_key_b64 = self._derive_shared_key(shared_secret)
        self._set_session(sender_username, sender_device_id, session_key_b64, "prekey-recipient")

        self.local_prekeys.pop(prekey_id, None)
        self._persist_local_prekeys()
        return True

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
        self._set_session(initiator_username, initiator_device_id, shared_key_b64, "responder")
        self.session_keys[initiator_username]["handshake_id"] = int(handshake["id"])
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
        self._set_session(recipient_username, recipient_device_id, shared_key_b64, "initiator")
        self.session_keys[recipient_username]["handshake_id"] = handshake_id
        self.finalized_handshakes.add(handshake_id)
        self.pending_initiator_keys.pop(handshake_id, None)
        return shared_key_b64

    def has_session_with(self, peer_username: str) -> bool:
        return peer_username in self.session_keys

    def session_peer_device_id(self, peer_username: str) -> str:
        entry = self.session_keys.get(peer_username) or {}
        return str(entry.get("peer_device_id", ""))

    def load_peer_public_key(self, peer, pem):
        self.session_keys[peer] = {
            "peer_identity_key": Ed25519PublicKey.from_public_bytes(
                serialization.load_pem_public_key(pem.encode("utf-8")).public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
        }

    def _message_key_bytes(self, peer: str) -> bytes:
        entry = self.session_keys.get(peer)
        if not entry:
            raise ValueError(f"No established session with {peer}")
        key_b64 = entry.get("session_key", "")
        if not key_b64:
            raise ValueError(f"Session key missing for {peer}")
        return base64.b64decode(str(key_b64).encode("utf-8"))

    def encrypt_message(self, peer: str, message: str, aad_obj: Dict[str, object]):
        key = self._message_key_bytes(peer)
        nonce = os.urandom(12)
        aad_json = json.dumps(aad_obj, sort_keys=True, separators=(",", ":"))
        session_entry = self.session_keys.get(peer) or {}
        bootstrap = session_entry.get("bootstrap") if isinstance(session_entry, dict) else None
        if bootstrap and str(session_entry.get("established_by", "")) == "prekey-initiator":
            merged_aad = dict(aad_obj)
            merged_aad.update({k: v for k, v in bootstrap.items() if k and v is not None})
            aad_json = json.dumps(merged_aad, sort_keys=True, separators=(",", ":"))
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, message.encode("utf-8"), aad_json.encode("utf-8"))
        return {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "aad": base64.b64encode(aad_json.encode("utf-8")).decode("utf-8"),
            "timestamp": int(time.time()),
        }

    def decrypt_message(self, sender: str, ciphertext_b64: str, nonce_b64: str, aad_b64: str):
        key = self._message_key_bytes(sender)
        aes = AESGCM(key)
        nonce = base64.b64decode(nonce_b64.encode("utf-8"))
        ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
        aad_json_bytes = base64.b64decode(aad_b64.encode("utf-8"))
        plaintext = aes.decrypt(nonce, ciphertext, aad_json_bytes)
        aad_obj = json.loads(aad_json_bytes.decode("utf-8"))
        return plaintext.decode("utf-8"), aad_obj
