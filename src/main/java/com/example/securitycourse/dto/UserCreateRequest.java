package com.example.securitycourse.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Set;

public class UserCreateRequest {

    @NotBlank @Size(min = 3, max = 100)
    private String username;

    @Email @Size(max = 200)
    private String email;

    @NotBlank @Size(min = 12, max = 200)
    private String password;

    private Set<String> roles;

    /** LOCAL / AD / EXTERNAL. По умолчанию LOCAL. */
    private String source;

    /** Для EXTERNAL: идентификатор контрагента. Для AD: DN. */
    private String externalId;

    /** Срок действия учётной записи (для EXTERNAL). */
    private Instant expiresAt;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public String getExternalId() { return externalId; }
    public void setExternalId(String externalId) { this.externalId = externalId; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
}