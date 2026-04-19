# Hybrid Cryptosystem — RSA-4096-OAEP + AES-256-GCM

> **Information Security Lab Mini Project**  
> Full-stack Zero-Knowledge Hybrid Cryptosystem with Digital Signatures, Tamper Detection, PBKDF2 password stretching, and Secure File Shredding.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    BROWSER (Zero-Knowledge)                     │
│                                                                 │
│  Plaintext File                                                 │
│       │                                                         │
│       ▼  AES-256-GCM (96-bit IV, 128-bit auth tag)             │
│  ┌──────────────┐    RSA-4096-OAEP(SHA-256)                    │
│  │  Ciphertext  │◄── AES Session Key ──────────────────────┐   │
│  └──────────────┘                                          │   │
│       │                                                    │   │
│       ▼  ECDSA-P256 / SHA-256                              │   │
│  ┌──────────────┐                                          │   │
│  │  Signature   │                                          │   │
│  └──────────────┘                                          │   │
│       │                                                    │   │
│       └──── Digital Envelope ──── POST /api/crypto/upload  │   │
│                                                            │   │
│  [Optional PBKDF2-SHA256 layer wraps AES key with password]│   │
└────────────────────────────────────────────────────────────┼───┘
                                                             │
┌────────────────────────────────────────────────────────────┼───┐
│                    SPRING BOOT SERVER                       │   │
│                                                            │   │
│  ┌─────────────────┐   ┌──────────────┐                   │   │
│  │  H2 Database    │   │  RSA-4096    │◄──────────────────┘   │
│  │  (Audit Log +   │   │  Private Key │  Decapsulation         │
│  │   Envelopes)    │   │  (In Memory) │  on /decrypt          │
│  └─────────────────┘   └──────────────┘                       │
│                                                                │
│  Server NEVER sees plaintext. Acts as KEM endpoint only.       │
└────────────────────────────────────────────────────────────────┘
```

---

## Algorithm Suite

| Layer           | Algorithm              | Parameters                              |
|-----------------|------------------------|-----------------------------------------|
| Symmetric Enc.  | AES-256-GCM            | 256-bit key, 96-bit IV, 128-bit auth tag |
| Key Encapsulatn | RSA-4096-OAEP          | SHA-256 hash + MGF1-SHA256              |
| Digital Sig.    | ECDSA P-256            | SHA-256 digest, FIPS 186-4              |
| Password KDF    | PBKDF2-SHA256          | 310,000 iterations, 128-bit salt        |
| Random source   | WebCrypto CSPRNG       | `window.crypto.getRandomValues`         |

---

## Project Structure

```
hybrid-crypto-system/
├── backend/
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/cryptosystem/
│       │   ├── HybridCryptoApplication.java
│       │   ├── config/CorsConfig.java
│       │   ├── controller/SecurityController.java   ← Main deliverable
│       │   ├── service/SecurityService.java
│       │   ├── model/{DigitalEnvelope,AuditLog}.java
│       │   ├── repository/*Repository.java
│       │   └── dto/DigitalEnvelopeDto.java
│       └── resources/application.properties
└── frontend/
    ├── package.json
    └── src/
        ├── crypto.js     ← WebCrypto utility (all browser crypto)
        ├── App.js        ← React dashboard
        └── App.css
```

---

## Quick Start

### Backend (Spring Boot)

```bash
cd backend
mvn spring-boot:run
# Server starts on http://localhost:8080
# RSA-4096 key generation takes ~15-30s on first boot
# H2 Console: http://localhost:8080/h2-console
```

### Frontend (React)

```bash
cd frontend
npm install
npm start
# Opens http://localhost:3000
```

---

## API Reference

| Method | Endpoint                      | Description                              |
|--------|-------------------------------|------------------------------------------|
| GET    | `/api/crypto/public-key`      | Server RSA-4096 public key (SPKI/Base64) |
| POST   | `/api/crypto/upload`          | Store digital envelope                   |
| GET    | `/api/crypto/envelopes`       | List all envelopes                       |
| POST   | `/api/crypto/decrypt/{id}`    | KEM decapsulation → return AES key       |
| POST   | `/api/crypto/verify/{id}`     | ECDSA signature verification             |
| POST   | `/api/crypto/tamper/{id}`     | [DEMO] Corrupt ciphertext byte           |
| DELETE | `/api/crypto/shred/{id}`      | Secure overwrite + delete                |
| GET    | `/api/crypto/audit-log`       | Retrieve audit log (last 100 events)     |

---

## Rubric Alignment (10 Marks)

| Criterion | Marks | Implementation                                                   |
|-----------|-------|------------------------------------------------------------------|
| Problem statement & objectives | 2 | Zero-knowledge hybrid KEM with tamper detection, non-repudiation, and PBKDF2 key hardening |
| Systems, variables & parameters | 2 | RSA-OAEP (4096-bit), AES-GCM (256-bit, 96-bit IV, 128-bit tag), ECDSA-P256, PBKDF2-SHA256 all clearly identified |
| Existing solutions & assumptions | 2 | Pure RSA (slow, size-limited) vs pure AES (key distribution problem) → Hybrid solves both; zero-knowledge assumption documented |
| Compare & select alternatives | 2 | GCM vs CBC (GCM provides AEAD — chosen), RSA-OAEP vs RSA-PKCS1v15 (OAEP is IND-CCA2 secure — chosen), ECDSA vs RSA-PSS |
| Read, understand & interpret | 2 | Real-time crypto variable log shows IVs, tag lengths, key bits, algorithm names; full audit trail in H2 |

---

## Key Security Properties

- **Zero-Knowledge Upload**: Plaintext never transmitted; all encryption is browser-side via WebCrypto API.
- **Authenticated Encryption**: AES-256-GCM provides confidentiality + integrity + authenticity in one primitive.
- **Tamper Detection**: 128-bit GCM authentication tag detects any single-bit modification to ciphertext.
- **Non-Repudiation**: ECDSA-P256 signature ties the ciphertext to the sender's session key pair.
- **Key Hardening**: PBKDF2-SHA256 with 310,000 iterations provides brute-force resistance for password layer.
- **Forward Secrecy (session)**: Signing key pair is ephemeral per browser session.
- **Secure Shredding**: Overwrite-before-null pattern prevents data recovery from DB page cache.

---

## Advantages of Hybrid Cryptosystems

1. **Performance**: AES-256-GCM encrypts data at hardware speed (GiB/s); RSA is used only for the small session key.
2. **Key Size**: RSA encrypts 32 bytes (AES key) efficiently; directly encrypting a file with RSA is impractical.
3. **Security**: Both algorithms can be attacked independently — an attacker must break both to recover plaintext.
4. **Authenticated Encryption**: GCM mode provides integrity for free, eliminating need for a separate MAC.

## Applications

- **Secure Email** (PGP/S-MIME use RSA + AES hybrid)
- **TLS 1.3** (ECDHE for key exchange + AES-GCM for data)
- **Encrypted Cloud Storage** (files encrypted locally, keys wrapped)
- **Digital Forensics** (encrypted evidence containers)
- **Healthcare** (HIPAA-compliant patient record encryption)
- **Financial Systems** (PCI-DSS compliant card data protection)
