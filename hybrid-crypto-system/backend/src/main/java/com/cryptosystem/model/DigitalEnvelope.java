package com.cryptosystem.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * Represents a stored Digital Envelope — a hybrid-encrypted file container.
 *
 * Structure:
 *   [ RSA-4096-OAEP( AES-256-GCM session key ) ]   ← encryptedAesKey
 *   [ AES-256-GCM( plaintext file )            ]   ← encryptedFile
 *   [ ECDSA-P256( encryptedFile bytes )         ]   ← signature
 *
 * The server NEVER holds the plaintext. Zero-knowledge architecture.
 */
@Entity
@Table(name = "digital_envelopes")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DigitalEnvelope {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // ─── File Metadata ─────────────────────────────────────────────────────
    @Column(nullable = false)
    private String fileName;

    @Column(nullable = false)
    private String fileType;

    private long fileSizeBytes;

    // ─── AES-256-GCM Ciphertext ────────────────────────────────────────────
    /** AES-256-GCM encrypted file (includes 128-bit GCM authentication tag appended by WebCrypto) */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String encryptedFileBase64;

    /** 96-bit (12-byte) random initialisation vector for AES-GCM */
    @Column(nullable = false)
    private String ivBase64;

    // ─── RSA-4096-OAEP Wrapped Session Key ────────────────────────────────
    /** AES-256 session key encrypted with server's RSA-4096-OAEP public key */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String encryptedAesKeyBase64;

    // ─── Digital Signature (ECDSA-P256) ───────────────────────────────────
    /** ECDSA-P256 / SHA-256 signature over the encrypted file bytes */
    @Column(columnDefinition = "TEXT")
    private String signatureBase64;

    /** Sender's ECDSA-P256 public key (SPKI/Base64) stored for verification */
    @Column(columnDefinition = "TEXT")
    private String signingPublicKeyBase64;

    // ─── PBKDF2 Optional Password Layer ───────────────────────────────────
    private boolean passwordProtected;

    /** PBKDF2 salt (Base64) — only set when passwordProtected=true */
    private String pbkdf2SaltBase64;

        // add after pbkdf2SaltBase64
    @Column(columnDefinition = "TEXT")
    private String pwWrappedAesKeyBase64;

    private String pwWrapIvBase64;

    // ─── Crypto Parameters (for audit transparency) ────────────────────────
    private String aesKeyBits;       // "256"
    private String ivBits;           // "96"
    private String tagBits;          // "128"
    private String rsaKeyBits;       // "4096"
    private String asymAlgorithm;    // "RSA-OAEP-SHA256"
    private String symAlgorithm;     // "AES-256-GCM"
    private String sigAlgorithm;     // "ECDSA-P256-SHA256"

    // ─── Lifecycle ─────────────────────────────────────────────────────────
    @Column(nullable = false)
    private LocalDateTime uploadedAt;

    private String uploaderIp;

    /** True after the Secure File Shred operation — data is overwritten */
    @Builder.Default
    private boolean shredded = false;

    private LocalDateTime shreddedAt;

    @PrePersist
    protected void onCreate() {
        if (uploadedAt == null) uploadedAt = LocalDateTime.now();
    }
}
