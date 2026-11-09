# Backend API

- `POST /api/session` — JSON `{ "master_key": "..." }`, generate a temporary keypair and protect a copy of its private key with Scrypt + AES-GCM.
- `GET /api/key` — return active public key.
- `POST /api/encrypt` — JSON `{ "text": "..." }`, returns encrypted packet.
- `POST /api/decrypt` — JSON `{ "packet": { ... } }`, authenticates and decrypts.
- `POST /api/export` — JSON `{ "packet": { ... } }`, returns an encrypted `.txt` note container.
- `POST /api/decrypt-saved` — JSON `{ "file_text": "...", "master_key": "..." }`, unwraps the private key and decrypts a saved `.txt` note.
- `POST /api/lock` — clear the active private key from process memory.
- `GET /health` — health check.

See the repository README for setup and important limitations.
