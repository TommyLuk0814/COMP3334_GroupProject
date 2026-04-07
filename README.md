# COMP3334_GroupProject

## Setup
1. Install dependencies:
    - `pip install -r requirements.txt`
2. Generate TLS certificate and key (for localhost, no OpenSSL required):
    - `mkdir server/certs`
    - `py server/generate_dev_cert.py`

## Run
1. Start server:
    - `py server/server.py`
2. Start client (new terminal):
    - `$env:IM_TLS_CA_CERT="server/certs/localhost.crt"` (PowerShell)
    - `echo $env:IM_TLS_CA_CERT`
    The output should be: server/certs/localhost.crt
    - `py client/main.py --profile user1`
    - `py client/main.py --profile user2`

## Implementation Status Checklist
- [x] R1 Registration
- [x] R2 Login with Password + OTP
- [x] R3 Logout / session invalidation
- [x] R4 Per-device identity keypair
- [x] R5 Fingerprint / verification UI
- [x] R6 Key change detection
- [x] R7 Secure session establishment
- [x] R8 Message encryption and authentication
- [x] R9 Replay protection / de-duplication
- [x] R10 TTL / expiration policy
- [x] R11 Client deletion behavior
- [x] R12 Server storage behavior (best-effort)
- [x] R13 Friend request workflow
- [x] R14 Request lifecycle
- [x] R15 Blocking / removing
- [x] R16 Default anti-spam control
- [x] R17 Minimum delivery states
- [x] R18 Define "Delivered" semantics
- [x] R19 Metadata disclosure statement
- [x] R20 Offline ciphertext queue
- [x] R21 Retention and cleanup
- [x] R22 Duplicate/replay robustness
- [x] R23 Conversation list
- [x] R24 Unread counters
- [x] R25 Paging / incremental loading

## Implementation Notes (How Each Requirement Is Met)
- R1 Registration: Server provides `/register` with unique username/contact code checks and password hashing before storing user records.
- R2 Login with Password + OTP: Login is split into password verification (`/login/password`) and TOTP verification (`/login/otp`) with token issuance bound to user/device.
- R3 Logout / session invalidation: Client clears local token on logout and server supports session/token expiry semantics.
- R4 Per-device identity keypair: Each client profile generates/stores local Ed25519 identity keys and uploads only public keys per device.
- R5 Fingerprint / verification UI: Client shows per-device fingerprints in `Keys / Fingerprint` dialog and stores local verified fingerprints.
- R6 Key change detection: Client tracks known fingerprints, shows persistent `[Key changed]` badge until re-verify, and uses allow-with-warning prompts on send.
- R7 Secure session establishment: Custom HbC-appropriate handshake + signed prekey bootstrap establish per-peer shared session keys.
- R8 Message encryption and authentication: Messages use AES-GCM with authenticated metadata (AAD) including sender/recipient/counter/TTL context.
- R9 Replay protection / de-duplication: Receiver tracks per-sender-device counters in a persisted replay window and drops duplicates/replays.
- R10 TTL / expiration policy: Sender includes TTL in authenticated metadata and computes expiry; `0`/empty is treated as non-expiring.
- R11 Client deletion behavior: Expired messages are pruned from UI and local persisted chat history.
- R12 Server storage behavior (best-effort): Server filters/cleans expired queued ciphertext on delivery paths and cleanup logic.
- R13 Friend request workflow: Add-contact flow is request-based (`send`, `accept`, `decline`, `cancel`) rather than instant friendship.
- R14 Request lifecycle: Client shows incoming/outgoing pending lists and supports accept/decline/cancel operations.
- R15 Blocking / removing: Blocking/removing supported; blocked pairs are prevented from normal interaction and queued undelivered messages are handled safely.
- R16 Default anti-spam control: Only friends can exchange chat messages by default; non-friends are limited to friend-request flow.
- R17 Minimum delivery states: Outgoing messages display at least `Sent` and `Delivered` states.
- R18 Define Delivered semantics: Delivered is based on recipient-side ACK returned to server, then exposed to sender status query.
- R19 Metadata disclosure statement: Delivery status is documented as revealing timing/online metadata to the HbC server.
- R20 Offline ciphertext queue: Server stores ciphertext for offline recipients and forwards when they come online.
- R21 Retention and cleanup: Retention policy combines post-delivery handling and TTL-respecting best-effort expiry cleanup.
- R22 Duplicate/replay robustness: Client safely handles retries/duplicates via persisted replay checks plus seen-message filtering.
- R23 Conversation list: Friend list is sorted by most recent conversation activity and shows last activity timestamp.
- R24 Unread counters: Per-conversation unread counts are maintained, displayed, persisted, and cleared on opening that conversation.
- R25 Paging / incremental loading: Chat window shows recent history first and loads older messages incrementally via `Load Older Messages`; page size is configurable in `client/config.py`.

## Security Implementation
- **Secure randomness**: All cryptographic keys (Ed25519 identity keys, X25519 session keys) and nonces are generated using `cryptography.hazmat` with `os.urandom()`, which is cryptographically secure on all platforms.
- **Secure local storage**: Private keys are encrypted at rest using `cryptography.fernet.Fernet` (AES-128-CBC with authentication). Local profile directories (`.client_profiles/`, `.identity_profiles/`) store encrypted key material and fingerprint state on disk.
- **Input validation**: Server validates all JSON payloads using Pydantic schemas; messages are size-limited; malformed prekey bundles or encrypted payloads are rejected with explicit errors.
- **Transport security**: All client-server communication uses TLS 1.2+ (HTTPS on port 8443). Self-signed certificates are generated via `server/generate_dev_cert.py` with proper Subject Alternative Names (localhost, 127.0.0.1, ::1); clients verify certificates using local CA cert or skip with `IM_TLS_INSECURE=1` (dev-only).
- **Minimal sensitive logging**: Debug-level logs do not include private keys, plaintext messages, or session secrets. Errors are logged at INFO level with sanitized context only.
- **Basic abuse controls**: Rate limiting enforced on `/register`, `/login/password`, and `/send_friend_request` endpoints (max 10 reqs/minute per IP/user). Blocked user pairs cannot interact; duplicate requests are ignored.
- **E2EE principles**: Message content confidentiality is enforced via AES-GCM with per-message random nonces; AAD includes sender/recipient/counter/TTL to bind integrity to conversation context. Server never has access to decryption keys.

## Project Overview 
In  this  project,  your  team  will  design  and  implement  a  secure  instant  messaging  (IM)  tool  with 
end-to-end encryption (E2EE). This project focuses on 1:1 private messaging only (no group chat 
requirement)  and  does  not  require  multi-device  message  synchronization.  You  may  implement 
the client as a desktop application and the server using any network stack 
(HTTP/WebSocket/gRPC,  etc.).  The  server  is  assumed  to  be  honest-but-curious:  it  follows  the 
protocol correctly but may inspect and analyze all data it can access. 
Your system must support the following required features: 
• E2EE 1:1 (peer-to-peer) private chat 
• Timed self-destruct messages 
• User registration and login (password + OTP) 
• Friend requests / contact management (request → accept/decline) 
• Offline messaging (ciphertext store-and-forward) 
• Message delivery status (at least Sent and Delivered) 
• Conversation list and unread counters

## Threat Model 
Your design must explicitly assume the following adversaries: 
• Server is honest-but-curious (HbC): it follows your protocol but may inspect databases, logs, 
and all application-layer data, and perform traffic analysis (timestamps, message sizes, 
contact graph). 
• Network attacker (external): may observe traffic and attempt Man-In-The-Middle (MTIM) if 
transport security is misconfigured; may cause packet duplication/reordering at lower layers. 
• Malicious users/clients: may create accounts, spam friend requests, send malformed 
messages, replay old ciphertexts, or attempt impersonation at the UI layer. 

## Security Goals 
Given the threat model above, your system must provide the following security guarantees: 
• End-to-end confidentiality against the server: the server must not be able to decrypt message 
contents. 
• End-to-end integrity and authentication between users: attackers should not forge/modify 
messages undetectably for a conversation they are not part of. 
• Replay resistance / de-duplication: duplicated or replayed ciphertext must not be accepted as 
new messages. 
• Key change visibility: if a contact’s identity key changes, the user must be warned and your 
policy must be explained.

## Library usage 
You may choose any programming language and cryptographic libraries. However, you must use 
well-reviewed libraries for cryptographic primitives (encryption, signatures, key agreement, 
hashing, random number generation). Do not implement cryptographic primitives from scratch. 

## Transport security 
Use TLS for client-server connections. E2EE protects message content from the server, but TLS 
is still required to defend against network attackers and credential theft.

## System Architecture 
Your system must include at least: 
• Client application(s) implementing the E2EE logic and UI. 
• Server handling registration/authentication, friend requests, public key distribution (or 
equivalent), message relay, and offline ciphertext queue storage. 
The server must never have access to the keys required to decrypt message contents. The server 
may store ciphertext for offline delivery. 

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

## Security Requirements 
• Secure randomness: keys/nonces come from a cryptographically secure RNG. 
• Secure local storage: protect private keys and protocol state at rest (e.g., OS keychain or 
encrypted local storage). 
• Input validation: reject malformed messages and enforce reasonable size limits. 
• Transport security: use TLS for client-server communication. 
• Minimal sensitive logging: do not log secrets; disable verbose debug logs by default. 
• Basic abuse controls: rate limit registration/login and friend requests.