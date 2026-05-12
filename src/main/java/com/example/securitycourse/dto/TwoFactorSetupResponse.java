package com.example.securitycourse.dto;

import java.util.List;

public class TwoFactorSetupResponse {
    private String secret;
    private String qrCodeDataUri;
    private List<String> backupCodes;

    public TwoFactorSetupResponse() {}

    public TwoFactorSetupResponse(String secret, String qrCodeDataUri) {
        this.secret = secret;
        this.qrCodeDataUri = qrCodeDataUri;
    }

    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }
    public String getQrCodeDataUri() { return qrCodeDataUri; }
    public void setQrCodeDataUri(String qrCodeDataUri) { this.qrCodeDataUri = qrCodeDataUri; }
    public List<String> getBackupCodes() { return backupCodes; }
    public void setBackupCodes(List<String> backupCodes) { this.backupCodes = backupCodes; }
}