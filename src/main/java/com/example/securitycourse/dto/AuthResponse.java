package com.example.securitycourse.dto;

public class AuthResponse {

    private String jwt;
    private long expiresIn;
    private boolean requireTwoFactor;
    private String twoFactorToken;

    public AuthResponse(String jwt, long expiresIn) {
        this.jwt = jwt;
        this.expiresIn = expiresIn;
        this.requireTwoFactor = false;
    }

    public AuthResponse(boolean requireTwoFactor, String twoFactorToken, long expiresIn) {
        this.jwt = null;
        this.expiresIn = expiresIn;
        this.requireTwoFactor = requireTwoFactor;
        this.twoFactorToken = twoFactorToken;
    }

    // Геттеры и сеттеры
    public String getJwt() { return jwt; }
    public void setJwt(String jwt) { this.jwt = jwt; }
    public long getExpiresIn() { return expiresIn; }
    public void setExpiresIn(long expiresIn) { this.expiresIn = expiresIn; }
    public boolean isRequireTwoFactor() { return requireTwoFactor; }
    public void setRequireTwoFactor(boolean requireTwoFactor) { this.requireTwoFactor = requireTwoFactor; }
    public String getTwoFactorToken() { return twoFactorToken; }
    public void setTwoFactorToken(String twoFactorToken) { this.twoFactorToken = twoFactorToken; }
}