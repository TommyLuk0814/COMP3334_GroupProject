# COMP3334_GroupProject

## Setup
1. Install dependencies (single source of truth):
    - `pip install -r requirements.txt`

## Run
1. Start backend:
    - `py server/server.py`
2. Start client (new terminal):
    - `py client/main.py`

## Implementation Status Checklist
- [x] R1 Registration
- [x] R2 Login with Password + OTP
- [x] R3 Logout / session invalidation
- [x] R4 Per-device identity keypair
- [ ] R5 Fingerprint / verification UI (partial: backend fingerprint/public key endpoints exist, full client fingerprint/verified UX pending)
- [ ] R6 Key change detection (partial: key change detection helper exists, full warning/block UI flow pending)
- [x] R7 Secure session establishment (implemented as signed X25519 handshake plus signed one-time prekey flow for offline first-message bootstrap)
- [x] R8 Message encryption and authentication
- [ ] R9 Replay protection / de-duplication
- [ ] R10 TTL / expiration policy
- [ ] R11 Client deletion behavior
- [ ] R12 Server storage behavior (best-effort)
- [x] R13 Friend request workflow
- [x] R14 Request lifecycle
- [ ] R15 Blocking / removing (partial: requests and new outbound messages are blocked; queued-before-block edge handling pending)
- [x] R16 Default anti-spam control
- [ ] R17 Minimum delivery states (partial: server returns sent/delivered states, sender-side delivered status UI is pending)
- [ ] R18 Define "Delivered" semantics (partial: delivered currently mapped to recipient ACK endpoint)
- [ ] R19 Metadata disclosure statement
- [x] R20 Offline ciphertext queue (including first-message support via prekey claim when recipient is offline)
- [ ] R21 Retention and cleanup
- [ ] R22 Duplicate/replay robustness
- [ ] R23 Conversation list
- [ ] R24 Unread counters
- [ ] R25 Paging / incremental loading

## Checklist Evidence Map
- R1-R3: `server/server.py`, `server/security.py`, `server/rate_limiter.py`, `server/database.py`, `client/api_client.py`, `client/ui.py`
- R4: `client/crypto_manager.py`, `server/server.py` (`/keys`), `server/database.py` (`identity_keys`)
- R5 (partial): `server/server.py` (`/keys/{username}/fingerprint`, `/keys/{username}`), `server/security.py` (`fingerprint_for_pem`)
- R6 (partial): `client/api_client.py` (`detect_key_change`)
- R7: `server/server.py` (`/sessions/*`, `/prekeys/*`), `server/database.py` (`session_handshakes`, `prekeys`), `client/crypto_manager.py` (X25519 handshake + prekey verify/derive), `client/ui.py` (auto handshake + prekey bootstrap flow)
- R8: `client/crypto_manager.py` (AES-GCM encrypt/decrypt with AAD), `server/server.py` (`/messages/send`, `/messages/poll`), `client/ui.py` (encrypted send + decrypt display)
- R13-R14: `server/server.py` (`/friends/request`, `/friends/requests/*`, `/friends`), `server/database.py` (`friend_requests`, `friendships`), `client/api_client.py`, `client/ui.py`
- R15 (partial): `server/server.py` (`/friends/remove`, `/friends/block`, `/friends/unblock`), `server/database.py` (`blocks`), `client/ui.py` (Block/Unblock)
- R16: `server/server.py` (`/messages/send` checks `are_friends`)
- R17 (partial): `server/server.py` (send returns `sent`, ack endpoint returns `delivered`), `server/database.py` (`delivered_at`)
- R18 (partial): `server/server.py` (`/messages/{message_id}/ack` used as delivered semantics)
- R20: `server/database.py` (`messages` queue, `prekeys`), `server/server.py` (`/messages/poll`, `/prekeys/{username}/claim`), `client/ui.py` (prekey-first send path)

## Functional Requirements
1. Accounts & Authentication 
    - (R1) Registration 
        - Users can register with a unique identifier (e.g., username or email). 
        - Passwords are stored using a modern password hashing scheme with a per-user salt. 
        - Basic password policy and rate limiting for registration/login. 
    - (R2) Login with Password + OTP 
        - Support login with password plus a second factor (OTP). 
        - Sessions/tokens must expire and be bound to the authenticated user. 
    - (R3) Logout / session invalidation 
        - Users can log out; tokens are expired/revoked promptly. 
2. Identity & Key Management 
    - (R4) Per-device identity keypair 
        - Each client generates and stores a long-term identity keypair locally. 
        - The server stores only the public key(s) needed for others to initiate secure sessions. 
    - (R5) Fingerprint / verification UI 
        - Show a user-visible fingerprint (or safety number) for each contact/device identity key. 
        - Allow the user to mark a contact as “verified” (local state is acceptable). 
    - (R6) Key change detection 
        - If a contact’s identity key changes, the client must warn the user. 
        - Define your policy (block until re-verified, or allow with warning) and justify it. 
3. E2EE 1:1 Messaging 
    - (R7) Secure session establishment 
        - You must implement a secure method for two users to establish shared secrets for messaging. This course does not require a specific design such as X3DH; you may choose any protocol that is appropriate under the HbC server model. Your report must describe the protocol, its assumptions, and the security properties it provides (and does not provide). 
    - (R8) Message encryption and authentication 
        - Each message must be protected with authenticated encryption (or an equivalent encrypt then-MAC design) to provide confidentiality and integrity. 
        - Bind relevant metadata using authenticated associated data (AD), such as sender/receiver identifiers, conversation ID, and message counters, so tampering is detected. 
    - (R9) Replay protection / de-duplication 
        - The receiver must detect and ignore replayed or duplicated ciphertext messages (within a reasonable window defined by your design). 
4. Timed Self-Destruct Messages 
    - (R10) TTL / expiration policy 
        - Support messages that self-destruct after a configurable time duration (e.g., 30 seconds, 10 minutes). 
        - Include the TTL/expiry policy in authenticated metadata so it cannot be altered without detection. 
    - (R11) Client deletion behavior 
        - Expired messages are removed from the UI and local storage. 
    - (R12) Server storage behavior (best-effort) 
        - If the server stores offline ciphertext, it must delete ciphertext after expiry (best-effort). 
    - Important limitations:
        - Self-destruct cannot prevent screenshots, copy/paste, or a malicious client. That is fine.  
5. Friends / Contacts 
    - (R13) Friend request workflow 
        - Users must add contacts via a request → accept/decline workflow (not instant adding by default). 
        - Users can send friend requests by username/email/contact code. 
    - (R14) Request lifecycle 
        - Receiver can accept or decline; sender can cancel; both can view pending requests. 
    - (R15) Blocking / removing 
        - Users can remove friends and block users; blocked users’ requests/messages are ignored. 
    - (R16) Default anti-spam control 
        - By default, non-friends must not be able to send arbitrary chat messages (only friend requests), or provide an equivalent control with justification. 
6. Message Delivery Status 
    - Delivery indicators are common IM usability features but can leak metadata. Under the HbC server model, you may rely on the server to behave correctly, but you must define the semantics precisely and discuss metadata exposure. 
    - (R17) Minimum delivery states 
        - Sent: client successfully submitted the message to the server. 
        - Delivered: message has reached the recipient side according to your defined semantics. 
    - (R18) Define “Delivered” semantics 
        - Option A (simplest): Delivered means the server placed ciphertext into the recipient’s queue or forwarded it to the recipient’s active connection. 
        - Option B (stronger semantics): Delivered means the recipient client sent an acknowledgement back to the sender (recommended to protect the ack with E2EE). 
    - (R19) Metadata disclosure statement 
        - State what the server learns from delivery status updates (e.g., online timing). 
7. Offline Messaging (Ciphertext Store-and-Forward) 
    - (R20) Offline ciphertext queue 
        - If the recipient is offline, the server queues messages as ciphertext and relays them when the recipient comes online. 
    - (R21) Retention and cleanup 
        - Define a retention policy (e.g., delete after delivery or after max age). 
        - Timed self-destruct TTL must be respected best-effort for queued ciphertext. 
    - (R22) Duplicate/replay robustness 
        - Clients must safely handle duplicates (e.g., from retries). 
        - Replay protection must prevent accepting old ciphertext as a new message. 
8. Conversation List & Unread Counters 
    - (R23) Conversation list 
        - Show a list of conversations (contacts) ordered by most recent activity, including last message time. 
    - (R24) Unread counters 
        - Maintain and display an unread count per conversation. 
    - (R25) Paging / incremental loading 
        - Implement basic pagination or incremental loading to avoid loading all history at once. 
9. UI 
    - To reduce your workload, your client application does not need a beautiful Graphical User Interface (GUI). A GUI that is necessary to be used or a CLI client is fine.  