package com.cryptosystem.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class SecurityServiceTest {

    private static final OAEPParameterSpec OAEP_PARAMS = new OAEPParameterSpec(
            "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT
    );

    private SecurityService securityService;

    @BeforeEach
    void setUp() throws Exception {
        securityService = new SecurityService();

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        KeyPair rsaKeyPair = rsaKpg.generateKeyPair();

        setPrivateField(securityService, "rsaKeyPair", rsaKeyPair);
    }

    @Test
    void decryptAesSessionKey_shouldReturnOriginalRawKey() throws Exception {
        byte[] rawAesKey = new byte[32];
        for (int i = 0; i < rawAesKey.length; i++) {
            rawAesKey[i] = (byte) i;
        }

        KeyPair rsaKeyPair = (KeyPair) getPrivateField(securityService, "rsaKeyPair");
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic(), OAEP_PARAMS);
        byte[] encrypted = cipher.doFinal(rawAesKey);

        byte[] decrypted = securityService.decryptAesSessionKey(Base64.getEncoder().encodeToString(encrypted));

        assertArrayEquals(rawAesKey, decrypted);
    }

    @Test
    void verifyEcdsaSignature_shouldReturnTrueForValidP1363Signature() throws Exception {
        byte[] data = "ciphertext-sample".getBytes();

        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair signingPair = ecKpg.generateKeyPair();

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(signingPair.getPrivate());
        signer.update(data);
        byte[] derSignature = signer.sign();
        byte[] p1363Signature = derToP1363(derSignature, 32);

        boolean verified = securityService.verifyEcdsaSignature(
                Base64.getEncoder().encodeToString(data),
                Base64.getEncoder().encodeToString(p1363Signature),
                Base64.getEncoder().encodeToString(signingPair.getPublic().getEncoded())
        );

        assertTrue(verified);
    }

    @Test
    void verifyEcdsaSignature_shouldReturnFalseForTamperedData() throws Exception {
        byte[] originalData = "ciphertext-sample".getBytes();
        byte[] tamperedData = "ciphertext-sample-tampered".getBytes();

        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair signingPair = ecKpg.generateKeyPair();

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(signingPair.getPrivate());
        signer.update(originalData);
        byte[] derSignature = signer.sign();
        byte[] p1363Signature = derToP1363(derSignature, 32);

        boolean verified = securityService.verifyEcdsaSignature(
                Base64.getEncoder().encodeToString(tamperedData),
                Base64.getEncoder().encodeToString(p1363Signature),
                Base64.getEncoder().encodeToString(signingPair.getPublic().getEncoded())
        );

        assertFalse(verified);
    }

    @Test
    void publicKeyFingerprint_shouldReturnColonSeparatedPrefix() {
        String fingerprint = securityService.publicKeyFingerprint();

        assertNotNull(fingerprint);
        assertTrue(fingerprint.matches("([0-9A-F]{2}:){7}[0-9A-F]{2}\\.\\.\\."));
    }

    private static byte[] derToP1363(byte[] der, int coordLen) {
        if (der.length < 8 || der[0] != 0x30) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature");
        }

        int idx = 2;
        if (der[idx++] != 0x02) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature (missing r)");
        }

        int rLen = der[idx++] & 0xFF;
        byte[] r = Arrays.copyOfRange(der, idx, idx + rLen);
        idx += rLen;

        if (der[idx++] != 0x02) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature (missing s)");
        }

        int sLen = der[idx++] & 0xFF;
        byte[] s = Arrays.copyOfRange(der, idx, idx + sLen);

        byte[] p1363 = new byte[coordLen * 2];
        leftPadUnsigned(r, p1363, 0, coordLen);
        leftPadUnsigned(s, p1363, coordLen, coordLen);
        return p1363;
    }

    private static void leftPadUnsigned(byte[] value, byte[] target, int offset, int len) {
        int srcStart = (value.length > 0 && value[0] == 0x00) ? 1 : 0;
        int srcLen = value.length - srcStart;
        if (srcLen > len) {
            srcStart += (srcLen - len);
            srcLen = len;
        }
        int pad = len - srcLen;
        Arrays.fill(target, offset, offset + pad, (byte) 0x00);
        System.arraycopy(value, srcStart, target, offset + pad, srcLen);
    }

    private static void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static Object getPrivateField(Object target, String fieldName) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(target);
    }
}
