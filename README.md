
# Ayra Vault 

A lightweight **client-side encrypted password & notes vault** that runs entirely in your browser.

No server. No tracking. Fully local encryption using Web Crypto API.

## Features

- AES-GCM encryption
- PBKDF2 key derivation
- Local encrypted storage
- Password & secure notes manager
- Zero backend
- Works offline

## Demo

Open directly in browser.


## Security Model

Master password → PBKDF2 → AES-256-GCM key  
Encrypted vault stored in localStorage

## Warning

If you forget the master password, the vault cannot be recovered.
