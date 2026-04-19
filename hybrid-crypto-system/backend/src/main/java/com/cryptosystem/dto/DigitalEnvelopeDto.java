package com.cryptosystem.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Payload sent by the browser after in-browser zero-knowledge encryption. */
@Data
public class DigitalEnvelopeDto {

    @NotBlank(message = "File name is required")
    private String fileName;

    private String fileType;
    private long   fileSizeBytes;

    // ─── AES-256-GCM ciphertext (GCM auth-tag appended by WebCrypto) ──────
    @NotBlank
    private String encryptedFileBase64;

    @NotBlank
    private String ivBase64;            // 96-bit IV

    // ─── RSA-4096-OAEP wrapped session key ────────────────────────────────
    @NotBlank
    private String encryptedAesKeyBase64;

    // ─── ECDSA-P256 digital signature ─────────────────────────────────────
    private String signatureBase64;
    private String signingPublicKeyBase64;

    // ─── PBKDF2 optional layer ────────────────────────────────────────────
    private boolean passwordProtected;
    private String  pbkdf2SaltBase64;
}
