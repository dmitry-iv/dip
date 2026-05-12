package com.example.securitycourse.dto;

import jakarta.validation.constraints.NotBlank;

public class TwoFactorVerifyRequest {

    @NotBlank
    private String mfaToken;

    @NotBlank
    private String code;

    public String getMfaToken() { return mfaToken; }
    public void setMfaToken(String mfaToken) { this.mfaToken = mfaToken; }
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }
}