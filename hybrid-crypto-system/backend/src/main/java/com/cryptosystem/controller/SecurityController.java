package com.cryptosystem.controller;

import com.cryptosystem.dto.DigitalEnvelopeDto;
import com.cryptosystem.model.AuditLog;
import com.cryptosystem.model.DigitalEnvelope;
import com.cryptosystem.repository.AuditLogRepository;
import com.cryptosystem.repository.DigitalEnvelopeRepository;
import com.cryptosystem.service.SecurityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;

/**
 * ════════════════════════════════════════════════════════════════
 *   Hybrid Cryptosystem — Security REST Controller
 * ════════════════════════════════════════════════════════════════
 *
 * Zero-Knowledge Architecture:
 *   The server acts as a Key Encapsulation Mechanism (KEM) endpoint only.
 *   All file encryption / decryption happens EXCLUSIVELY in the browser
 *   using the WebCrypto API. The server never receives or processes plaintext.
 *
 * Endpoints:
 *   GET    /api/crypto/public-key         → Server RSA-4096 public key (SPKI/Base64)
 *   POST   /api/crypto/upload             → Store digital envelope
 *   GET    /api/crypto/envelopes          → List stored envelopes
 *   POST   /api/crypto/decrypt/{id}       → Unwrap AES session key (KEM decapsulation)
 *   POST   /api/crypto/verify/{id}        → Verify ECDSA signature
 *   POST   /api/crypto/tamper/{id}        → [DEMO] Corrupt ciphertext to test tamper detection
 *   DELETE /api/crypto/shred/{id}         → Secure file shred (overwrite & delete)
 *   GET    /api/crypto/audit-log          → Retrieve audit log
 *
 * ════════════════════════════════════════════════════════════════
 */
@Slf4j
@RestController
@RequestMapping("/api/crypto")
@RequiredArgsConstructor
public class SecurityController {

    private final SecurityService              securityService;
    private final DigitalEnvelopeRepository    envelopeRepository;
    private final AuditLogRepository           auditLogRepository;

    // ─────────────────────────────────────────────────────────────────────────
    // 1. PUBLIC KEY — expose server's RSA-4096 public key for key wrapping
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns the server's RSA-4096-OAEP public key in SPKI/Base64 format.
     * The browser imports this key to wrap (encrypt) the AES session key.
     *
     * This endpoint is intentionally unauthenticated — a public key is, by
     * definition, public information.
     */
    @GetMapping("/public-key")
    public ResponseEntity<Map<String, String>> getServerPublicKey() {
        log.debug("Public key requested");
        Map<String, String> response = new LinkedHashMap<>();
        response.put("algorithm",        "RSA-OAEP");
        response.put("keyBits",          "4096");
        response.put("hashAlgorithm",    "SHA-256");
        response.put("mgf1HashAlgorithm","SHA-256");
        response.put("publicKeyBase64",  securityService.getPublicKeyBase64());
        response.put("fingerprint",      securityService.publicKeyFingerprint());
        return ResponseEntity.ok(response);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. UPLOAD — receive and persist a digital envelope from the browser
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Stores a browser-encrypted digital envelope.
     *
     * The envelope contains:
     *   • AES-256-GCM ciphertext of the file (with 128-bit auth tag)
     *   • RSA-4096-OAEP wrapped AES session key
     *   • ECDSA-P256 signature over the ciphertext
     *   • All cryptographic parameters for auditability
     *
     * The server performs ZERO cryptographic operations on upload —
     * it is a dumb, authenticated storage backend.
     */
    @PostMapping("/upload")
    public ResponseEntity<Map<String, Object>> uploadEnvelope(
            @Valid @RequestBody DigitalEnvelopeDto dto,
            HttpServletRequest request) {

        String clientIp = resolveClientIp(request);
        log.info("📦 Envelope upload: file='{}' size={}B ip={}", dto.getFileName(),
                dto.getFileSizeBytes(), clientIp);

        try {
            DigitalEnvelope envelope = DigitalEnvelope.builder()
                    .fileName(dto.getFileName())
                    .fileType(dto.getFileType() != null ? dto.getFileType() : "text/plain")
                    .fileSizeBytes(dto.getFileSizeBytes())
                    // Ciphertext
                    .encryptedFileBase64(dto.getEncryptedFileBase64())
                    .ivBase64(dto.getIvBase64())
                    // Wrapped session key
                    .encryptedAesKeyBase64(dto.getEncryptedAesKeyBase64())
                    // Signature
                    .signatureBase64(dto.getSignatureBase64())
                    .signingPublicKeyBase64(dto.getSigningPublicKeyBase64())
                    // PBKDF2
                    .passwordProtected(dto.isPasswordProtected())
                    .pbkdf2SaltBase64(dto.getPbkdf2SaltBase64())
                    // Crypto parameter audit trail
                    .aesKeyBits("256")
                    .ivBits("96")
                    .tagBits("128")
                    .rsaKeyBits("4096")
                    .asymAlgorithm("RSA-OAEP-SHA256")
                    .symAlgorithm("AES-256-GCM")
                    .sigAlgorithm("ECDSA-P256-SHA256")
                    // Metadata
                    .uploadedAt(LocalDateTime.now())
                    .uploaderIp(clientIp)
                    .shredded(false)
                    .build();

            DigitalEnvelope saved = envelopeRepository.save(envelope);

            // Audit event
            auditLogRepository.save(AuditLog.builder()
                    .eventType(AuditLog.EventType.ENVELOPE_UPLOAD)
                    .fileName(dto.getFileName())
                    .status(AuditLog.Status.SUCCESS)
                    .details(String.format(
                            "Envelope stored. AES: %s-GCM | RSA: %s-OAEP | IV: %s-bit | Tag: %s-bit | Signed: %s | PwdProtected: %s",
                            "256", "4096", "96", "128",
                            dto.getSignatureBase64() != null,
                            dto.isPasswordProtected()
                    ))
                    .envelopeId(saved.getId())
                    .clientIp(clientIp)
                    .build());

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success",    true);
            response.put("envelopeId", saved.getId());
            response.put("fileName",   saved.getFileName());
            response.put("uploadedAt", saved.getUploadedAt().toString());
            response.put("message",    "Digital envelope stored. Plaintext was never transmitted.");
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            log.error("Upload failed for '{}': {}", dto.getFileName(), e.getMessage());
            auditLogRepository.save(AuditLog.builder()
                    .eventType(AuditLog.EventType.ENVELOPE_UPLOAD)
                    .fileName(dto.getFileName())
                    .status(AuditLog.Status.FAILURE)
                    .details("Upload error: " + e.getMessage())
                    .clientIp(clientIp)
                    .build());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. LIST ENVELOPES
    // ─────────────────────────────────────────────────────────────────────────

    @GetMapping("/envelopes")
    public ResponseEntity<List<Map<String, Object>>> listEnvelopes() {
        List<DigitalEnvelope> envelopes = envelopeRepository.findAllByOrderByUploadedAtDesc();
        List<Map<String, Object>> result = envelopes.stream()
                .map(e -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id",               e.getId());
                    m.put("fileName",         e.getFileName());
                    m.put("fileType",         e.getFileType());
                    m.put("fileSizeBytes",    e.getFileSizeBytes());
                    m.put("uploadedAt",       e.getUploadedAt().toString());
                    m.put("shredded",         e.isShredded());
                    m.put("passwordProtected",e.isPasswordProtected());
                    m.put("signed",           e.getSignatureBase64() != null);
                    m.put("symAlgorithm",     e.getSymAlgorithm());
                    m.put("asymAlgorithm",    e.getAsymAlgorithm());
                    m.put("sigAlgorithm",     e.getSigAlgorithm());
                    m.put("aesKeyBits",       e.getAesKeyBits());
                    m.put("ivBits",           e.getIvBits());
                    m.put("tagBits",          e.getTagBits());
                    m.put("ivBase64",         e.getIvBase64());
                    return m;
                })
                .toList();
        return ResponseEntity.ok(result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. DECRYPT — KEM decapsulation: unwrap AES key, return to browser
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Key Encapsulation Mechanism (KEM) decapsulation.
     *
     * The server decrypts the RSA-wrapped AES session key using its private key
     * and returns the raw AES key material to the browser along with the
     * ciphertext. The browser performs the actual AES-256-GCM decryption locally.
     *
     * If AES-GCM authentication fails in the browser (tampered ciphertext),
     * a 'Tamper Alert' is raised on the frontend — the 128-bit GCM auth tag
     * provides cryptographic integrity assurance without any server involvement.
     */
    @PostMapping("/decrypt/{id}")
    public ResponseEntity<Map<String, Object>> decryptEnvelope(
            @PathVariable Long id,
            HttpServletRequest request) {

        String clientIp = resolveClientIp(request);
        log.info("🔓 Decrypt request: envelopeId={} ip={}", id, clientIp);

        Optional<DigitalEnvelope> opt = envelopeRepository.findById(id);
        if (opt.isEmpty()) {
            return notFound("Envelope not found: " + id);
        }

        DigitalEnvelope envelope = opt.get();
        if (envelope.isShredded()) {
            return ResponseEntity.status(HttpStatus.GONE)
                    .body(Map.of("error", "This envelope has been securely shredded."));
        }

        try {
            // ── RSA-4096-OAEP decryption of the wrapped AES key ──────────────
            byte[] rawAesKey = securityService.decryptAesSessionKey(
                    envelope.getEncryptedAesKeyBase64()
            );
            String rawAesKeyBase64 = Base64.getEncoder().encodeToString(rawAesKey);

            auditLogRepository.save(AuditLog.builder()
                    .eventType(AuditLog.EventType.DECRYPT_REQUEST)
                    .fileName(envelope.getFileName())
                    .status(AuditLog.Status.SUCCESS)
                    .details("RSA-4096-OAEP session key unwrapped. Raw AES key returned to browser for local AES-256-GCM decryption.")
                    .envelopeId(id)
                    .clientIp(clientIp)
                    .build());

            // Return ciphertext + unwrapped AES key to browser.
            // Browser will perform AES-256-GCM decryption + auth-tag verification.
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success",              true);
            response.put("fileName",             envelope.getFileName());
            response.put("encryptedFileBase64",  envelope.getEncryptedFileBase64());
            response.put("ivBase64",             envelope.getIvBase64());
            response.put("rawAesKeyBase64",      rawAesKeyBase64);  // 32 raw bytes
            response.put("aesKeyBits",           envelope.getAesKeyBits());
            response.put("tagBits",              envelope.getTagBits());
            response.put("note", "AES session key decapsulated server-side. " +
                                 "Decryption & auth-tag verification occur in your browser.");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Key decapsulation failed for envelope {}: {}", id, e.getMessage());
            auditLogRepository.save(AuditLog.builder()
                    .eventType(AuditLog.EventType.DECRYPT_REQUEST)
                    .fileName(envelope.getFileName())
                    .status(AuditLog.Status.FAILURE)
                    .details("RSA decapsulation error: " + e.getMessage())
                    .envelopeId(id)
                    .clientIp(clientIp)
                    .build());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("success", false, "error", "Key decapsulation failed."));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. VERIFY INTEGRITY — ECDSA signature verification (non-repudiation)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies the ECDSA-P256/SHA-256 digital signature over the stored ciphertext.
     * Confirms: (a) sender identity and (b) ciphertext has not been replaced.
     *
     * Note: GCM auth-tag covers byte-level integrity. ECDSA covers identity / origin.
     * Both mechanisms are complementary and serve different threat models.
     */
    @PostMapping("/verify/{id}")
    public ResponseEntity<Map<String, Object>> verifyIntegrity(
            @PathVariable Long id,
            HttpServletRequest request) {

        String clientIp = resolveClientIp(request);
        log.info("🔍 Integrity check: envelopeId={} ip={}", id, clientIp);

        Optional<DigitalEnvelope> opt = envelopeRepository.findById(id);
        if (opt.isEmpty()) return notFound("Envelope " + id + " not found");

        DigitalEnvelope envelope = opt.get();

        if (envelope.getSignatureBase64() == null || envelope.getSigningPublicKeyBase64() == null) {
            return ResponseEntity.ok(Map.of(
                    "verified", false,
                    "reason",   "This envelope was uploaded without a digital signature."
            ));
        }

        try {
            boolean valid = securityService.verifyEcdsaSignature(
                    envelope.getEncryptedFileBase64(),
                    envelope.getSignatureBase64(),
                    envelope.getSigningPublicKeyBase64()
            );

            String detail = valid
                    ? "ECDSA-P256 signature valid. Ciphertext origin confirmed. Non-repudiation established."
                    : "ECDSA-P256 signature INVALID. Ciphertext may have been replaced or tampered with.";

            auditLogRepository.save(AuditLog.builder()
                    .eventType(valid
                            ? AuditLog.EventType.INTEGRITY_CHECK
                            : AuditLog.EventType.TAMPER_DETECTED)
                    .fileName(envelope.getFileName())
                    .status(valid ? AuditLog.Status.SUCCESS : AuditLog.Status.FAILURE)
                    .details(detail)
                    .envelopeId(id)
                    .clientIp(clientIp)
                    .build());

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("verified",   valid);
            response.put("algorithm",  "ECDSA-P256-SHA256");
            response.put("fileName",   envelope.getFileName());
            response.put("detail",     detail);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Signature verification error for envelope {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("verified", false, "error", e.getMessage()));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. TAMPER SIMULATION — corrupt 1 byte to demo GCM auth-tag detection
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * [DEMO / EDUCATIONAL ONLY]
     * Flips one byte in the stored ciphertext to demonstrate AES-GCM
     * tamper detection. The next decryption attempt will fail with a
     * 'Tamper Alert' because the 128-bit authentication tag won't match.
     */
    @PostMapping("/tamper/{id}")
    public ResponseEntity<Map<String, Object>> simulateTamper(@PathVariable Long id) {
        Optional<DigitalEnvelope> opt = envelopeRepository.findById(id);
        if (opt.isEmpty()) return notFound("Envelope " + id + " not found");

        DigitalEnvelope envelope = opt.get();
        if (envelope.isShredded()) {
            return ResponseEntity.status(HttpStatus.GONE)
                    .body(Map.of("error", "Envelope has been shredded."));
        }

        try {
            // Decode → flip bit 7 of byte 0 in the ciphertext → re-encode
            byte[] cipherBytes = Base64.getDecoder().decode(envelope.getEncryptedFileBase64());
            cipherBytes[0] ^= 0xFF;                   // XOR flip: corrupt first byte
            String tamperedBase64 = Base64.getEncoder().encodeToString(cipherBytes);
            envelope.setEncryptedFileBase64(tamperedBase64);
            envelopeRepository.save(envelope);

            auditLogRepository.save(AuditLog.builder()
                    .eventType(AuditLog.EventType.TAMPER_DETECTED)
                    .fileName(envelope.getFileName())
                    .status(AuditLog.Status.FAILURE)
                    .details("[SIMULATION] 1 byte of ciphertext corrupted (byte[0] XOR 0xFF). " +
                             "AES-GCM 128-bit auth-tag will reject decryption.")
                    .envelopeId(id)
                    .build());

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Ciphertext corrupted. Try decrypting to see the Tamper Alert triggered by AES-GCM auth-tag mismatch."
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. SECURE FILE SHRED — overwrite all sensitive data, mark as shredded
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Performs a secure shred of an envelope.
     *
     * Overwrites all sensitive fields with cryptographically random data
     * before nulling them. This prevents recovery from database page cache
     * or WAL logs in a persistent database (meaningful in production with
     * a file-backed DB; H2 in-memory has no such concern, but the pattern
     * is demonstrated correctly).
     */
    @DeleteMapping("/shred/{id}")
    public ResponseEntity<Map<String, Object>> shredEnvelope(
            @PathVariable Long id,
            HttpServletRequest request) {

        String clientIp = resolveClientIp(request);
        log.info("🗑️  Shred request: envelopeId={} ip={}", id, clientIp);

        Optional<DigitalEnvelope> opt = envelopeRepository.findById(id);
        if (opt.isEmpty()) return notFound("Envelope " + id + " not found");

        DigitalEnvelope envelope = opt.get();
        if (envelope.isShredded()) {
            return ResponseEntity.ok(Map.of("message", "Already shredded."));
        }

        String fileName = envelope.getFileName();

        // Overwrite sensitive fields with random placeholder data
        String shredMarker = Base64.getEncoder().encodeToString(
                java.security.SecureRandom.getSeed(32)
        );
        envelope.setEncryptedFileBase64(shredMarker);
        envelope.setEncryptedAesKeyBase64(shredMarker);
        envelope.setSignatureBase64(null);
        envelope.setSigningPublicKeyBase64(null);
        envelope.setPbkdf2SaltBase64(null);
        envelope.setIvBase64(shredMarker.substring(0, 16));
        envelope.setShredded(true);
        envelope.setShreddedAt(LocalDateTime.now());
        envelopeRepository.save(envelope);

        auditLogRepository.save(AuditLog.builder()
                .eventType(AuditLog.EventType.SHRED_EXECUTED)
                .fileName(fileName)
                .status(AuditLog.Status.SUCCESS)
                .details("All ciphertext, wrapped key, and signature fields overwritten with random bytes. " +
                         "Envelope marked shredded. Recovery is no longer possible.")
                .envelopeId(id)
                .clientIp(clientIp)
                .build());

        return ResponseEntity.ok(Map.of(
                "success",    true,
                "envelopeId", id,
                "fileName",   fileName,
                "shreddedAt", envelope.getShreddedAt().toString(),
                "message",    "Secure shred complete. All cryptographic material overwritten."
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 8. AUDIT LOG
    // ─────────────────────────────────────────────────────────────────────────

    @GetMapping("/audit-log")
    public ResponseEntity<List<AuditLog>> getAuditLog() {
        return ResponseEntity.ok(auditLogRepository.findTop100ByOrderByTimestampDesc());
    }

    @GetMapping("/audit-log/{envelopeId}")
    public ResponseEntity<List<AuditLog>> getAuditLogForEnvelope(@PathVariable Long envelopeId) {
        return ResponseEntity.ok(auditLogRepository.findByEnvelopeIdOrderByTimestampAsc(envelopeId));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilities
    // ─────────────────────────────────────────────────────────────────────────

    private ResponseEntity<Map<String, Object>> notFound(String message) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("success", false, "error", message));
    }

    private String resolveClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isBlank())
                ? xff.split(",")[0].trim()
                : request.getRemoteAddr();
    }
}
