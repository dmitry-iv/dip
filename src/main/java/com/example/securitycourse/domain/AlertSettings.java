package com.example.securitycourse.domain;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "alert_settings")
public class AlertSettings {

    @Id
    @Column(name = "id")
    private Short id = 1;

    @Column(name = "smtp_host", nullable = false)
    private String smtpHost = "smtp.yandex.ru";

    @Column(name = "smtp_port", nullable = false)
    private Integer smtpPort = 587;

    @Column(name = "smtp_username", nullable = false)
    private String smtpUsername = "";

    @Column(name = "smtp_password", nullable = false, length = 1024)
    private String smtpPassword = "";

    @Column(name = "sender_address", nullable = false)
    private String senderAddress = "";

    @Column(name = "recipients_csv", nullable = false, length = 2000)
    private String recipientsCsv = "";

    @Column(name = "min_severity", nullable = false)
    private Integer minSeverity = 4;

    @Column(name = "throttle_seconds", nullable = false)
    private Integer throttleSeconds = 60;

    @Column(name = "enabled", nullable = false)
    private Boolean enabled = Boolean.FALSE;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @PreUpdate
    public void onUpdate() {
        this.updatedAt = Instant.now();
    }

    public Short getId() { return id; }
    public void setId(Short id) { this.id = id; }
    public String getSmtpHost() { return smtpHost; }
    public void setSmtpHost(String smtpHost) { this.smtpHost = smtpHost; }
    public Integer getSmtpPort() { return smtpPort; }
    public void setSmtpPort(Integer smtpPort) { this.smtpPort = smtpPort; }
    public String getSmtpUsername() { return smtpUsername; }
    public void setSmtpUsername(String smtpUsername) { this.smtpUsername = smtpUsername; }
    public String getSmtpPassword() { return smtpPassword; }
    public void setSmtpPassword(String smtpPassword) { this.smtpPassword = smtpPassword; }
    public String getSenderAddress() { return senderAddress; }
    public void setSenderAddress(String senderAddress) { this.senderAddress = senderAddress; }
    public String getRecipientsCsv() { return recipientsCsv; }
    public void setRecipientsCsv(String recipientsCsv) { this.recipientsCsv = recipientsCsv; }
    public Integer getMinSeverity() { return minSeverity; }
    public void setMinSeverity(Integer minSeverity) { this.minSeverity = minSeverity; }
    public Integer getThrottleSeconds() { return throttleSeconds; }
    public void setThrottleSeconds(Integer throttleSeconds) { this.throttleSeconds = throttleSeconds; }
    public Boolean getEnabled() { return enabled; }
    public void setEnabled(Boolean enabled) { this.enabled = enabled; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}