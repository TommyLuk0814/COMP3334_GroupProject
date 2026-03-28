import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class CryptoManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.session_keys = {}
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
