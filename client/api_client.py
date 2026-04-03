import json
from pathlib import Path
import time
import uuid

import requests

API_BASE_URL = "http://127.0.0.1:8000"


class IMClientAPI:
    def __init__(self, profile_name="default"):
        self.token = None
        self.current_user = None
        self.profile_name = self._normalize_profile_name(profile_name)
        self.profile_dir = Path(__file__).resolve().parent / ".client_profiles" / self.profile_name
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        self.device_id = self._load_or_create_device_id()
        self.known_keys_path = self.profile_dir / ".known_contact_keys.json"
        self.verified_keys_path = self.profile_dir / ".verified_contact_keys.json"
        self.replay_state_path = self.profile_dir / ".message_replay_state.json"
        self.sender_counter_state_path = self.profile_dir / ".sender_counter_state.json"
        self.chat_history_dir = self.profile_dir / ".chat_history"
        self.chat_history_dir.mkdir(parents=True, exist_ok=True)

    def _normalize_profile_name(self, profile_name):
        raw = (str(profile_name or "default")).strip().lower()
        sanitized = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in raw)
        return sanitized or "default"

    def _load_or_create_device_id(self):
        device_path = self.profile_dir / ".device_id"
        if device_path.exists():
            value = device_path.read_text(encoding="utf-8").strip()
            if value:
                return value

        generated = f"device-{uuid.uuid4().hex}"
        device_path.write_text(generated, encoding="utf-8")
        return generated

    def register(self, username, password):
        try:
            resp = requests.post(
                f"{API_BASE_URL}/register",
                json={"username": username, "password": password},
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        data = resp.json()
        self.current_user = username
        return True, {"otp_secret": data["otp_secret"], "contact_code": data.get("contact_code", "")}

    def verify_login_password(self, username, password):
        try:
            resp_pw = requests.post(
                f"{API_BASE_URL}/login/password",
                json={"username": username, "password": password},
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp_pw.status_code != 200:
            try:
                detail = resp_pw.json().get("detail", resp_pw.text)
            except Exception:
                detail = resp_pw.text
            return False, detail

        self.current_user = username
        return True, "OTP required"

    def login_with_otp(self, username, password, otp):
        try:
            resp_otp = requests.post(
                f"{API_BASE_URL}/login/otp",
                json={
                    "username": username,
                    "password": password,
                    "otp": otp,
                    "device_id": self.device_id,
                },
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp_otp.status_code != 200:
            try:
                detail = resp_otp.json().get("detail", resp_otp.text)
            except Exception:
                detail = resp_otp.text
            return False, detail
        data = resp_otp.json()
        self.token = data["access_token"]
        self.current_user = username
        return True, self.token

    def set_public_key(self, public_key_pem):
        if not self.token:
            return False
        try:
            resp = requests.post(
                f"{API_BASE_URL}/keys",
                json={"public_key_pem": public_key_pem},
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=5,
                verify=False,
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def get_public_key(self, username):
        if not self.token:
            return []
        try:
            resp = requests.get(
                f"{API_BASE_URL}/keys/{username}",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=5,
                verify=False,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            return data.get("keys", [])
        except requests.RequestException:
            return []

    def upload_prekeys(self, prekeys):
        if not self.token:
            return False, "Not authenticated"
        payload = {"prekeys": prekeys or []}
        try:
            resp = requests.post(
                f"{API_BASE_URL}/prekeys/upload",
                json=payload,
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def claim_prekey_bundle(self, username, device_id=""):
        if not self.token:
            return False, "Not authenticated"
        params = {}
        if device_id:
            params["device_id"] = device_id
        try:
            resp = requests.get(
                f"{API_BASE_URL}/prekeys/{username}/claim",
                params=params,
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def detect_key_change(self, username, remote_keys):
        known = self._load_known_keys()
        remote_fingerprints = sorted(k.get("fingerprint", "") for k in remote_keys)
        previous = known.get(username, [])
        has_changed = previous and previous != remote_fingerprints
        known[username] = remote_fingerprints
        self._save_known_keys(known)
        return has_changed

    def _load_known_keys(self):
        if not self.known_keys_path.exists():
            return {}
        try:
            return json.loads(self.known_keys_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_known_keys(self, data):
        self.known_keys_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_verified_keys(self):
        if not self.verified_keys_path.exists():
            return {}
        try:
            data = json.loads(self.verified_keys_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
            return {}
        except Exception:
            return {}

    def _save_verified_keys(self, data):
        self.verified_keys_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_verified_fingerprints(self, username):
        """
        Return a set of fingerprints for the given contact that the user
        has locally marked as 'verified'.
        """
        store = self._load_verified_keys()
        entries = store.get(str(username).strip().lower(), [])
        if not isinstance(entries, list):
            return set()
        return set(str(fp) for fp in entries)

    def set_verified_fingerprints(self, username, fingerprints):
        """
        Persist the set of fingerprints the user considers verified for a contact.
        """
        key = str(username).strip().lower()
        store = self._load_verified_keys()
        store[key] = sorted(set(str(fp) for fp in fingerprints))
        self._save_verified_keys(store)

    def _load_replay_state(self):
        if not self.replay_state_path.exists():
            return {"peers": {}}
        try:
            data = json.loads(self.replay_state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                peers = data.get("peers", {})
                if isinstance(peers, dict):
                    return {"peers": peers}
            return {"peers": {}}
        except Exception:
            return {"peers": {}}

    def _save_replay_state(self, data):
        self.replay_state_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_sender_counter_state(self):
        if not self.sender_counter_state_path.exists():
            return {"last_counter": 0}
        try:
            data = json.loads(self.sender_counter_state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                last_counter = int(data.get("last_counter", 0))
                if last_counter < 0:
                    last_counter = 0
                return {"last_counter": last_counter}
            return {"last_counter": 0}
        except Exception:
            return {"last_counter": 0}

    def _save_sender_counter_state(self, data):
        self.sender_counter_state_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def next_sender_counter(self):
        state = self._load_sender_counter_state()
        last_counter = int(state.get("last_counter", 0))
        now_counter = int(time.time() * 1000)
        counter = now_counter if now_counter > last_counter else (last_counter + 1)
        state["last_counter"] = counter
        self._save_sender_counter_state(state)
        return counter

    def _chat_history_path(self, username):
        normalized = self._normalize_profile_name(username)
        return self.chat_history_dir / f"{normalized}.json"

    def load_chat_history(self, username):
        path = self._chat_history_path(username)
        if not path.exists():
            return {"friends": {}}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("friends", {}), dict):
                return {"friends": data.get("friends", {})}
        except Exception:
            pass
        return {"friends": {}}

    def save_chat_history(self, username, data):
        path = self._chat_history_path(username)
        path.write_text(json.dumps(data or {"friends": {}}, indent=2), encoding="utf-8")

    def is_replay_message(self, sender_username, sender_device_id, sender_counter, window_size=256):
        key = f"{str(sender_username).strip().lower()}|{str(sender_device_id).strip()}"
        try:
            counter = int(sender_counter)
        except Exception:
            return False

        state = self._load_replay_state()
        peers = state.setdefault("peers", {})
        entry = peers.get(key, {})
        recent = entry.get("recent_counters", [])
        if not isinstance(recent, list):
            recent = []

        normalized_recent = []
        seen = set()
        for value in recent:
            try:
                number = int(value)
            except Exception:
                continue
            if number in seen:
                continue
            seen.add(number)
            normalized_recent.append(number)

        if counter in seen:
            return True

        normalized_recent.append(counter)
        if len(normalized_recent) > window_size:
            normalized_recent = normalized_recent[-window_size:]

        peers[key] = {"recent_counters": normalized_recent}
        self._save_replay_state(state)
        return False

    def _auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def get_me(self):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.get(
                f"{API_BASE_URL}/me",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def send_friend_request(self, identifier):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.post(
                f"{API_BASE_URL}/friends/request",
                json={"identifier": identifier.strip()},
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                body = resp.json()
                detail = body.get("detail", resp.text)
                if isinstance(detail, list):
                    detail = str(detail)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def list_incoming_friend_requests(self):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.get(
                f"{API_BASE_URL}/friends/requests/incoming",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json().get("requests", [])

    def list_outgoing_friend_requests(self):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.get(
                f"{API_BASE_URL}/friends/requests/outgoing",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json().get("requests", [])

    def accept_friend_request(self, request_id):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.post(
                f"{API_BASE_URL}/friends/requests/{int(request_id)}/accept",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def decline_friend_request(self, request_id):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.post(
                f"{API_BASE_URL}/friends/requests/{int(request_id)}/decline",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def cancel_friend_request(self, request_id):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.post(
                f"{API_BASE_URL}/friends/requests/{int(request_id)}/cancel",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def list_friends(self):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.get(
                f"{API_BASE_URL}/friends",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json().get("friends", [])

    def remove_friend(self, identifier):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.post(
                f"{API_BASE_URL}/friends/remove",
                json={"identifier": identifier.strip()},
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                body = resp.json()
                detail = body.get("detail", resp.text)
                if isinstance(detail, list):
                    detail = str(detail)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def block_user(self, identifier):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.post(
                f"{API_BASE_URL}/friends/block",
                json={"identifier": identifier.strip()},
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                body = resp.json()
                detail = body.get("detail", resp.text)
                if isinstance(detail, list):
                    detail = str(detail)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def unblock_user(self, identifier):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.post(
                f"{API_BASE_URL}/friends/unblock",
                json={"identifier": identifier.strip()},
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                body = resp.json()
                detail = body.get("detail", resp.text)
                if isinstance(detail, list):
                    detail = str(detail)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def list_blocked_users(self):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.get(
                f"{API_BASE_URL}/friends/blocks",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json().get("blocked_users", [])

    def block_friend_request(self, request_id):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.post(
                f"{API_BASE_URL}/friends/requests/{int(request_id)}/block",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def init_session_handshake(self, target_username, target_device_id, initiator_ephemeral_pub, initiator_signature):
        if not self.token:
            return False, "Not authenticated"
        payload = {
            "target_username": target_username,
            "target_device_id": target_device_id or "",
            "initiator_ephemeral_pub": initiator_ephemeral_pub,
            "initiator_signature": initiator_signature,
        }
        try:
            resp = requests.post(
                f"{API_BASE_URL}/sessions/init",
                json=payload,
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def list_pending_session_handshakes(self):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.get(
                f"{API_BASE_URL}/sessions/pending",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json().get("handshakes", [])

    def respond_session_handshake(self, handshake_id, responder_ephemeral_pub, responder_signature):
        if not self.token:
            return False, "Not authenticated"
        payload = {
            "responder_ephemeral_pub": responder_ephemeral_pub,
            "responder_signature": responder_signature,
        }
        try:
            resp = requests.post(
                f"{API_BASE_URL}/sessions/{int(handshake_id)}/respond",
                json=payload,
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def list_responded_session_handshakes(self):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.get(
                f"{API_BASE_URL}/sessions/responded",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json().get("handshakes", [])

    def send_message(self, recipient, recipient_device_id, ciphertext, nonce, aad, sender_counter, expires_in_seconds=0):
        if not self.token:
            return False, "Not authenticated"
        payload = {
            "recipient_username": recipient,
            "recipient_device_id": recipient_device_id or "",
            "ciphertext": ciphertext,
            "nonce": nonce,
            "aad": aad,
            "sender_counter": int(sender_counter),
            "expires_in_seconds": int(expires_in_seconds),
        }
        try:
            resp = requests.post(
                f"{API_BASE_URL}/messages/send",
                json=payload,
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()

    def get_messages(self):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.get(
                f"{API_BASE_URL}/messages/poll",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json().get("messages", [])

    def ack_message(self, message_id):
        if not self.token:
            return False, "Not authenticated"
        try:
            resp = requests.post(
                f"{API_BASE_URL}/messages/{int(message_id)}/ack",
                headers=self._auth_headers(),
                timeout=5,
                verify=False,
            )
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        if resp.status_code != 200:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            return False, detail
        return True, resp.json()
