# SSN Cryptographic Identifier Service

This project is a secure API service written in Rust that generates unique cryptographic tokens for Social Security Numbers (SSNs). It enhances data security by ensuring that SSNs are never exposed in plaintext, even to third-party services. Instead, services interact with encrypted tokens, which can be verified and rotated via the API.

## Features

- **Secure Encryption**: Uses AES-256-GCM and SHA-256 for cryptographic operations.
- **Token Management**: Generate, verify, and rotate tokens to protect user identity.
- **REST API**: Endpoints for registration, verification, and token rotation.
- **Database Storage**: SQLite for storing encrypted data securely.
- **Scalable Design**: Built with Rust for performance and safety.

## Prerequisites

- Rust (latest stable version)
- SQLite
- Environment variable for encryption key (`ENCRYPTION_KEY`)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/ssn-crypto-service.git
   cd ssn-crypto-service
