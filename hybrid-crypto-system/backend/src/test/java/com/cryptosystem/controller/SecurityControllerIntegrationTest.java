package com.cryptosystem.controller;

import com.cryptosystem.model.DigitalEnvelope;
import com.cryptosystem.repository.AuditLogRepository;
import com.cryptosystem.repository.DigitalEnvelopeRepository;
import com.cryptosystem.service.SecurityService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DigitalEnvelopeRepository envelopeRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @MockBean
    private SecurityService securityService;

    @BeforeEach
    void setUp() throws Exception {
        auditLogRepository.deleteAll();
        envelopeRepository.deleteAll();

        when(securityService.getPublicKeyBase64()).thenReturn("PUBLIC_KEY_BASE64");
        when(securityService.publicKeyFingerprint()).thenReturn("AA:BB:CC:DD:EE:FF:11:22...");
        when(securityService.decryptAesSessionKey(anyString())).thenReturn(new byte[]{1, 2, 3, 4});
        when(securityService.verifyEcdsaSignature(anyString(), anyString(), anyString())).thenReturn(true);
    }

    @Test
    void getPublicKey_shouldReturnExpectedCryptoMetadata() throws Exception {
        mockMvc.perform(get("/api/crypto/public-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.algorithm").value("RSA-OAEP"))
                .andExpect(jsonPath("$.keyBits").value("4096"))
                .andExpect(jsonPath("$.hashAlgorithm").value("SHA-256"))
                .andExpect(jsonPath("$.mgf1HashAlgorithm").value("SHA-256"))
                .andExpect(jsonPath("$.publicKeyBase64").value("PUBLIC_KEY_BASE64"))
                .andExpect(jsonPath("$.fingerprint").value("AA:BB:CC:DD:EE:FF:11:22..."));
    }

    @Test
    void uploadThenList_shouldPersistAndReturnEnvelope() throws Exception {
        String uploadBody = """
                {
                  "fileName": "message.txt",
                  "fileType": "text/plain",
                  "fileSizeBytes": 12,
                  "encryptedFileBase64": "Y2lwaGVydGV4dA==",
                  "ivBase64": "aXYtMTIzNDU2Nzg5MDE=",
                  "encryptedAesKeyBase64": "ZW5jcnlwdGVkLWFlcy1rZXk=",
                  "signatureBase64": "c2lnbmF0dXJl",
                  "signingPublicKeyBase64": "cHVia2V5",
                  "passwordProtected": false
                }
                """;

        mockMvc.perform(post("/api/crypto/upload")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(uploadBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.envelopeId").isNumber())
                .andExpect(jsonPath("$.fileName").value("message.txt"));

        mockMvc.perform(get("/api/crypto/envelopes"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].fileName").value("message.txt"))
                .andExpect(jsonPath("$[0].passwordProtected").value(false))
                .andExpect(jsonPath("$[0].symAlgorithm").value("AES-256-GCM"));
    }

    @Test
    void decrypt_shouldReturnRawAesKeyForNonPasswordProtectedEnvelope() throws Exception {
        DigitalEnvelope envelope = baseEnvelope();
        envelope.setPasswordProtected(false);
        envelope = envelopeRepository.save(envelope);

        mockMvc.perform(post("/api/crypto/decrypt/{id}", envelope.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.passwordProtected").value(false))
                .andExpect(jsonPath("$.rawAesKeyBase64").value("AQIDBA=="));
    }

    @Test
    void decrypt_shouldReturnPasswordWrapMaterialForPasswordProtectedEnvelope() throws Exception {
        DigitalEnvelope envelope = baseEnvelope();
        envelope.setPasswordProtected(true);
        envelope.setPbkdf2SaltBase64("c2FsdA==");
        envelope.setPwWrappedAesKeyBase64("cHctd3JhcHBlZC1rZXk=");
        envelope.setPwWrapIvBase64("cHctaXY=");
        envelope = envelopeRepository.save(envelope);

        mockMvc.perform(post("/api/crypto/decrypt/{id}", envelope.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.passwordProtected").value(true))
                .andExpect(jsonPath("$.pwWrappedAesKeyBase64").value("cHctd3JhcHBlZC1rZXk="))
                .andExpect(jsonPath("$.pwWrapIvBase64").value("cHctaXY="))
                .andExpect(jsonPath("$.pbkdf2SaltBase64").value("c2FsdA=="))
                .andExpect(jsonPath("$.rawAesKeyBase64").doesNotExist());
    }

    @Test
    void verify_shouldReturnFalseWhenSignatureMissing() throws Exception {
        DigitalEnvelope envelope = baseEnvelope();
        envelope.setSignatureBase64(null);
        envelope.setSigningPublicKeyBase64(null);
        envelope = envelopeRepository.save(envelope);

        mockMvc.perform(post("/api/crypto/verify/{id}", envelope.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(false))
                .andExpect(jsonPath("$.reason", containsString("without a digital signature")));
    }

    @Test
    void shred_shouldMarkEnvelopeAsShredded() throws Exception {
        DigitalEnvelope envelope = envelopeRepository.save(baseEnvelope());

        mockMvc.perform(delete("/api/crypto/shred/{id}", envelope.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.envelopeId").value(envelope.getId()));

        DigitalEnvelope updated = envelopeRepository.findById(envelope.getId()).orElseThrow();
        assert updated.isShredded();
    }

    @Test
    void upload_shouldReturnBadRequestWhenRequiredFieldsMissing() throws Exception {
        String invalidBody = """
                {
                  "fileType": "text/plain"
                }
                """;

        mockMvc.perform(post("/api/crypto/upload")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidBody))
                .andExpect(status().isBadRequest());
    }

    private static DigitalEnvelope baseEnvelope() {
        return DigitalEnvelope.builder()
                .fileName("doc.txt")
                .fileType("text/plain")
                .fileSizeBytes(20)
                .encryptedFileBase64("ZW5jcnlwdGVkLWJ5dGVz")
                .ivBase64("aXY=")
                .encryptedAesKeyBase64("ZW5jcnlwdGVkLWtleQ==")
                .signatureBase64("c2ln")
                .signingPublicKeyBase64("cHVi")
                .passwordProtected(false)
                .aesKeyBits("256")
                .ivBits("96")
                .tagBits("128")
                .rsaKeyBits("4096")
                .asymAlgorithm("RSA-OAEP-SHA256")
                .symAlgorithm("AES-256-GCM")
                .sigAlgorithm("ECDSA-P256-SHA256")
                .uploadedAt(LocalDateTime.now())
                .uploaderIp("127.0.0.1")
                .shredded(false)
                .build();
    }
}
