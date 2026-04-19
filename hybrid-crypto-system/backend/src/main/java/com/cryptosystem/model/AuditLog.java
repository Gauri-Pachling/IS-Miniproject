package com.cryptosystem.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * Immutable audit record for every cryptographic event.
 * Supports non-repudiation requirements and forensic analysis.
 */
@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_event_type", columnList = "eventType"),
    @Index(name = "idx_audit_timestamp",  columnList = "timestamp")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    public enum EventType {
        KEY_GENERATED,   // Server RSA key pair initialised
        ENVELOPE_UPLOAD, // New digital envelope stored
        DECRYPT_REQUEST, // AES session key decrypted by server
        INTEGRITY_CHECK, // ECDSA signature verified
        SHRED_EXECUTED,  // Secure file shred performed
        TAMPER_DETECTED  // Auth-tag verification failed
    }

    public enum Status { SUCCESS, FAILURE }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private EventType eventType;

    @Column(nullable = false)
    private String fileName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Status status;

    @Column(columnDefinition = "TEXT")
    private String details;

    private Long envelopeId;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    private String clientIp;

    @PrePersist
    protected void onCreate() {
        if (timestamp == null) timestamp = LocalDateTime.now();
    }
}
