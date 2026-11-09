# CryptoPad — ElGamal educational encryption demo

## Run locally

Requires Python 3.10+.

```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:8080 (or http://localhost:8080). Do not open the HTML files directly; the Flask API must be running. Set the `PORT` environment variable before starting the app to use a different port.

## What works

- Creates a temporary ElGamal public/private keypair.
- Encrypts plaintext using ElGamal ephemeral key agreement, HKDF-SHA256 and AES-256-GCM.
- Saves notes as readable `.txt` containers holding encrypted content and a master-key-protected private key.
- Decrypts saved note files with the master key, including after the server restarts.
- Copies the public key / packet and saves the encrypted note as a `.txt` file.
- Locking the workspace clears the active key from process memory.

## Important security limitations

This is an educational prototype, not a production secure-notes product. The ElGamal group arithmetic is implemented in this application using Python big integers; the symmetric authenticated encryption, HKDF, and Scrypt key wrapping use the `cryptography` package. It has not had a security audit. The active private key is held in process memory for the current session; each saved `.txt` file also contains a copy wrapped with the master key. Anyone with the file can attempt offline guesses against that master key, so choose a strong, unique key and keep it safe. If it is lost, the file cannot be decrypted. Do not enter passwords, personal data, or other sensitive information. Use a standardized, reviewed hybrid-encryption protocol and vetted key management for real applications.

The backend binds to 127.0.0.1 by default and has debug mode disabled.
