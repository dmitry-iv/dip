package com.example.securitycourse.dto;

public class AuthResponse {

    private String accessToken;
    private String tokenType = "Bearer";
    private long expiresIn;
    private boolean mfaPending;
    private String status;

    public AuthResponse() {}

    public static AuthResponse full(String token, long ttl) {
        AuthResponse r = new AuthResponse();
        r.accessToken = token;
        r.expiresIn = ttl;
        r.mfaPending = false;
        r.status = "AUTHENTICATED";
        return r;
    }

    public static AuthResponse mfaPending(String pendingToken, long ttl) {
        AuthResponse r = new AuthResponse();
        r.accessToken = pendingToken;
        r.expiresIn = ttl;
        r.mfaPending = true;
        r.status = "MFA_REQUIRED";
        return r;
    }

    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
    public long getExpiresIn() { return expiresIn; }
    public void setExpiresIn(long expiresIn) { this.expiresIn = expiresIn; }
    public boolean isMfaPending() { return mfaPending; }
    public void setMfaPending(boolean mfaPending) { this.mfaPending = mfaPending; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}