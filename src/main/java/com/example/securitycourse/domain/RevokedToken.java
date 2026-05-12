package com.example.securitycourse.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "revoked_tokens")
public class RevokedToken {

    @Id
    @Column(name = "jti")
    private UUID jti;

    @Column(name = "revoked_at", nullable = false)
    private Instant revokedAt = Instant.now();

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "reason", length = 100)
    private String reason;

    public RevokedToken() {
    }

    public RevokedToken(UUID jti, Instant expiresAt, UUID userId, String reason) {
        this.jti = jti;
        this.expiresAt = expiresAt;
        this.userId = userId;
        this.reason = reason;
    }

    public UUID getJti() { return jti; }
    public void setJti(UUID jti) { this.jti = jti; }

    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
}