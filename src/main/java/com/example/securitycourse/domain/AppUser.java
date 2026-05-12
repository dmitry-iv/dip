package com.example.securitycourse.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
public class AppUser {

    public enum Source {
        /** Локальная учётная запись (администраторы). */
        LOCAL,
        /** Внешний пользователь (контрагенты, аудиторы) — обязательно с 2FA. */
        EXTERNAL
    }

    @Id
    @GeneratedValue
    @UuidGenerator
    private UUID id;

    @Column(name = "username", nullable = false, unique = true, length = 100)
    private String username;

    @Column(name = "email", unique = true, length = 200)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 200)
    private String passwordHash;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts = 0;

    @Column(name = "lock_until")
    private Instant lockUntil;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    // ===== 2FA =====
    @Column(name = "totp_secret", length = 64)
    private String totpSecret;

    @Column(name = "totp_enabled", nullable = false)
    private boolean totpEnabled = false;

    @Column(name = "totp_enrolled_at")
    private Instant totpEnrolledAt;

    /** JSON-массив BCrypt-хешей backup-кодов. */
    @Column(name = "backup_codes", columnDefinition = "text")
    private String backupCodes;

    // ===== Источник пользователя =====
    @Enumerated(EnumType.STRING)
    @Column(name = "user_source", nullable = false, length = 20)
    private Source source = Source.LOCAL;

    /** DN из AD или ID контрагента (для EXTERNAL). */
    @Column(name = "external_id", length = 200)
    private String externalId;

    /** Срок действия учётной записи (для EXTERNAL). */
    @Column(name = "expires_at")
    private Instant expiresAt;

    // ===== Информация о последнем входе (для корреляции) =====
    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "last_login_ip", length = 64)
    private String lastLoginIp;

    @Column(name = "last_login_country", length = 2)
    private String lastLoginCountry;

    // ===== Роли =====
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    public AppUser() {
    }

    @PreUpdate
    public void onUpdate() {
        this.updatedAt = Instant.now();
    }

    /** Заблокирован ли пользователь на текущий момент. */
    public boolean isLockedNow(Instant now) {
        return lockUntil != null && lockUntil.isAfter(now);
    }

    /** Истёк ли срок действия учётной записи. */
    public boolean isExpired(Instant now) {
        return expiresAt != null && expiresAt.isBefore(now);
    }

    /** Требуется ли проверка 2FA. */
    public boolean requiresMfa() {
        // EXTERNAL — всегда обязательно. Остальные — если у них включён TOTP.
        return source == Source.EXTERNAL || totpEnabled;
    }

    // ============ Getters / Setters ============

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public void setFailedLoginAttempts(int failedLoginAttempts) { this.failedLoginAttempts = failedLoginAttempts; }

    public Instant getLockUntil() { return lockUntil; }
    public void setLockUntil(Instant lockUntil) { this.lockUntil = lockUntil; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }

    public String getTotpSecret() { return totpSecret; }
    public void setTotpSecret(String totpSecret) { this.totpSecret = totpSecret; }

    public boolean isTotpEnabled() { return totpEnabled; }
    public void setTotpEnabled(boolean totpEnabled) { this.totpEnabled = totpEnabled; }

    public Instant getTotpEnrolledAt() { return totpEnrolledAt; }
    public void setTotpEnrolledAt(Instant totpEnrolledAt) { this.totpEnrolledAt = totpEnrolledAt; }

    public String getBackupCodes() { return backupCodes; }
    public void setBackupCodes(String backupCodes) { this.backupCodes = backupCodes; }

    public Source getSource() { return source; }
    public void setSource(Source source) { this.source = source; }

    public String getExternalId() { return externalId; }
    public void setExternalId(String externalId) { this.externalId = externalId; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }

    public Instant getLastLoginAt() { return lastLoginAt; }
    public void setLastLoginAt(Instant lastLoginAt) { this.lastLoginAt = lastLoginAt; }

    public String getLastLoginIp() { return lastLoginIp; }
    public void setLastLoginIp(String lastLoginIp) { this.lastLoginIp = lastLoginIp; }

    public String getLastLoginCountry() { return lastLoginCountry; }
    public void setLastLoginCountry(String lastLoginCountry) { this.lastLoginCountry = lastLoginCountry; }

    public Set<Role> getRoles() { return roles; }
    public void setRoles(Set<Role> roles) { this.roles = roles; }
}