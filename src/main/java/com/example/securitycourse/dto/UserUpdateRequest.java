package com.example.securitycourse.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Set;

public class UserUpdateRequest {

    @Size(min = 3, max = 100)
    private String username;

    @Email @Size(max = 200)
    private String email;

    private Boolean enabled;
    private Set<String> roles;

    private String source;
    private Instant expiresAt;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public Boolean getEnabled() { return enabled; }
    public void setEnabled(Boolean enabled) { this.enabled = enabled; }
    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
}