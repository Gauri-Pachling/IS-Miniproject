package com.cryptosystem.service;

import com.cryptosystem.model.AuditLog;
import com.cryptosystem.repository.AuditLogRepository;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * Core cryptographic service.
 *
 * RSA-4096-OAEP key pair is generated once on startup and held in memory.
 * The private key NEVER leaves this service — the server acts as a Key
 * Encapsulation Mechanism (KEM) endpoint only.
 *
 * Algorithm interop matrix (must match WebCrypto API in browser):
 *   RSA-OAEP  : SHA-256 for label hash AND MGF1 mask generation
 *   Signature  : ECDSA with P-256 curve, SHA-256 digest
 */
@Slf4j
@Service
public class SecurityService {

    // ─── RSA-4096 Key Pair (server's KEM key) ────────────────────────────
    private KeyPair rsaKeyPair;

    @Getter
    private String publicKeyBase64;   // SPKI/DER → Base64, safe to expose

    @Autowired
    private AuditLogRepository auditLogRepository;

    // ─── OAEP parameters matching WebCrypto { name: 'RSA-OAEP', hash: 'SHA-256' }
    private static final OAEPParameterSpec OAEP_PARAMS = new OAEPParameterSpec(
            "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT
    );

    /**
     * Generates the server RSA-4096 key pair at application startup.
     * This may take 10-30 seconds — expected behaviour for 4096-bit keys.
     */
    @PostConstruct
    public void initialiseKeyPair() {
        try {
            log.info("⚙️  Generating RSA-4096 key pair — this may take a moment...");
            long start = System.currentTimeMillis();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(4096, new SecureRandom());
            rsaKeyPair = kpg.generateKeyPair();
            publicKeyBase64 = Base64.getEncoder().encodeToString(
                    rsaKeyPair.getPublic().getEncoded()
            );

            long elapsed = System.currentTimeMillis() - start;
            log.info("✅  RSA-4096 key pair ready in {}ms", elapsed);

            auditLogRepository.save(AuditLog.builder()
                    .eventType(AuditLog.EventType.KEY_GENERATED)
                    .fileName("SERVER")
                    .status(AuditLog.Status.SUCCESS)
                    .details("RSA-4096-OAEP key pair generated in " + elapsed + "ms. " +
                             "Public key fingerprint: " + publicKeyFingerprint())
                    .build());

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA not available in JCA provider", e);
        }
    }

    /**
     * Decrypts a browser-wrapped AES-256 session key using the server's RSA private key.
     *
     * @param encryptedAesKeyBase64 Base64-encoded RSA-OAEP ciphertext from browser
     * @return raw 32-byte AES-256 key material
     */
    public byte[] decryptAesSessionKey(String encryptedAesKeyBase64) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedAesKeyBase64);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate(), OAEP_PARAMS);

        return cipher.doFinal(encryptedBytes);
    }

    /**
     * Verifies an ECDSA-P256/SHA-256 signature produced by the browser's WebCrypto API.
     *
     * @param dataBase64         Base64-encoded data that was signed (encrypted file bytes)
     * @param signatureBase64    Base64-encoded DER signature
     * @param publicKeyBase64    Base64-encoded SPKI public key of the signer
     */
    public boolean verifyEcdsaSignature(String dataBase64,
                                        String signatureBase64,
                                        String publicKeyBase64) throws Exception {
        byte[] data      = Base64.getDecoder().decode(dataBase64);
        byte[] sigBytes  = Base64.getDecoder().decode(signatureBase64);
        byte[] pubBytes  = Base64.getDecoder().decode(publicKeyBase64);

        // Import ECDSA public key from SPKI bytes
        KeyFactory kf         = KeyFactory.getInstance("EC");
        PublicKey  signingKey = kf.generatePublic(new X509EncodedKeySpec(pubBytes));

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(signingKey);
        sig.update(data);

        return sig.verify(sigBytes);
    }

    /**
     * SHA-256 fingerprint of the server's RSA public key — displayed in the UI.
     */
    public String publicKeyFingerprint() {
        try {
            MessageDigest md     = MessageDigest.getInstance("SHA-256");
            byte[]        digest = md.digest(rsaKeyPair.getPublic().getEncoded());
            StringBuilder sb     = new StringBuilder();
            for (int i = 0; i < Math.min(8, digest.length); i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", digest[i]));
            }
            return sb + "...";
        } catch (NoSuchAlgorithmException e) {
            return "N/A";
        }
    }
}
