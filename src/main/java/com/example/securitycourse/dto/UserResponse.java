package com.example.securitycourse.dto;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public class UserResponse {

    private UUID id;
    private String username;
    private String email;
    private boolean enabled;
    private int failedLoginAttempts;
    private Instant lockUntil;
    private Set<String> roles;

    private String source;
    private Instant expiresAt;
    private boolean totpEnabled;

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public void setFailedLoginAttempts(int failedLoginAttempts) { this.failedLoginAttempts = failedLoginAttempts; }
    public Instant getLockUntil() { return lockUntil; }
    public void setLockUntil(Instant lockUntil) { this.lockUntil = lockUntil; }
    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public boolean isTotpEnabled() { return totpEnabled; }
    public void setTotpEnabled(boolean totpEnabled) { this.totpEnabled = totpEnabled; }
}