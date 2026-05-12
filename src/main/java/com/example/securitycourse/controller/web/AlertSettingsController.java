package com.example.securitycourse.controller.web;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.domain.AlertSettings;
import com.example.securitycourse.service.AlertSettingsService;
import com.example.securitycourse.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/admin/alert-settings")
@PreAuthorize("hasRole('ADMIN')")
public class AlertSettingsController {

    private static final Logger log = LoggerFactory.getLogger(AlertSettingsController.class);

    private final AlertSettingsService service;
    private final AuditService auditService;

    public AlertSettingsController(AlertSettingsService service, AuditService auditService) {
        this.service = service;
        this.auditService = auditService;
    }

    @GetMapping
    public String page(Model model) {
        AlertSettings s = service.load();
        boolean hasPassword = s.getSmtpPassword() != null && !s.getSmtpPassword().isBlank();
        // На форму пароль не передаём — в HTML-форме он только для ввода нового
        s.setSmtpPassword("");
        if (!model.containsAttribute("settings")) {
            model.addAttribute("settings", s);
        }
        model.addAttribute("hasPassword", hasPassword);
        return "admin/alert-settings";
    }

    @PostMapping("/save")
    public String save(@ModelAttribute("settings") AlertSettings form,
                       HttpServletRequest request,
                       RedirectAttributes ra) {
        try {
            // Загружаем старые настройки чтобы понять что изменилось
            AlertSettings before = service.load();
            service.save(form);

            // Аудит изменения конфигурации
            String changes = buildChangesDescription(before, form);
            auditService.logCurrent(request,
                    AuditActions.CONFIG_CHANGED, AuditResults.SUCCESS,
                    "AlertSettings", "1",
                    "Alert/SMTP configuration changed: " + changes);

            ra.addFlashAttribute("savedOk", "Настройки сохранены");
        } catch (Exception e) {
            log.error("Save alert settings failed", e);
            // Аудит неудачи тоже пишем — это важная информация для расследований
            try {
                auditService.logCurrent(request,
                        AuditActions.CONFIG_CHANGED, AuditResults.FAIL,
                        "AlertSettings", "1",
                        "Failed to save alert settings: " + e.getMessage());
            } catch (Exception ignored) {}
            ra.addFlashAttribute("errorMsg", "Ошибка сохранения: " + e.getMessage());
        }
        return "redirect:/admin/alert-settings";
    }

    @PostMapping("/test-connection")
    public String testConnection(HttpServletRequest request, RedirectAttributes ra) {
        AlertSettings s = service.load();
        try {
            service.testConnection(s);
            auditService.logCurrent(request,
                    AuditActions.CONFIG_CHANGED, AuditResults.SUCCESS,
                    "AlertSettings", "test-connection",
                    "SMTP connection test successful (host=" + s.getSmtpHost() + ":" + s.getSmtpPort() + ")");
            ra.addFlashAttribute("savedOk", "Подключение к SMTP-серверу успешно");
        } catch (Exception e) {
            log.warn("SMTP test failed: {}", e.getMessage());
            ra.addFlashAttribute("errorMsg", "Не удалось подключиться: " + e.getMessage());
        }
        return "redirect:/admin/alert-settings";
    }

    @PostMapping("/test-send")
    public String testSend(HttpServletRequest request, RedirectAttributes ra) {
        AlertSettings s = service.load();
        try {
            service.sendTestEmail(s);
            auditService.logCurrent(request,
                    AuditActions.CONFIG_CHANGED, AuditResults.SUCCESS,
                    "AlertSettings", "test-send",
                    "Test email sent successfully to: " + s.getRecipientsCsv());
            ra.addFlashAttribute("savedOk", "Тестовое письмо отправлено");
        } catch (Exception e) {
            log.warn("Test send failed: {}", e.getMessage());
            ra.addFlashAttribute("errorMsg", "Не удалось отправить: " + e.getMessage());
        }
        return "redirect:/admin/alert-settings";
    }

    /** Формирует человекочитаемое описание изменённых полей. */
/** Формирует человекочитаемое описание изменённых полей. */
    private String buildChangesDescription(AlertSettings before, AlertSettings after) {
        StringBuilder sb = new StringBuilder();
        if (!equalsNullable(before.getSmtpHost(), after.getSmtpHost())) {
            sb.append("smtpHost ").append(after.getSmtpHost()).append("; ");
        }
        if (!equalsNullable(
                before.getSmtpPort() == null ? null : before.getSmtpPort().toString(),
                after.getSmtpPort() == null ? null : after.getSmtpPort().toString())) {
            sb.append("smtpPort ").append(after.getSmtpPort()).append("; ");
        }
        if (!equalsNullable(before.getSmtpUsername(), after.getSmtpUsername())) {
            sb.append("smtpUsername ").append(after.getSmtpUsername()).append("; ");
        }
        // Пароль не логируем (значение), только факт изменения
        if (after.getSmtpPassword() != null && !after.getSmtpPassword().isBlank()) {
            sb.append("smtpPassword [updated]; ");
        }
        if (!equalsNullable(before.getSenderAddress(), after.getSenderAddress())) {
            sb.append("sender ").append(after.getSenderAddress()).append("; ");
        }
        if (!equalsNullable(before.getRecipientsCsv(), after.getRecipientsCsv())) {
            sb.append("recipients ").append(after.getRecipientsCsv()).append("; ");
        }
        if (!equalsNullable(
                before.getMinSeverity() == null ? null : before.getMinSeverity().toString(),
                after.getMinSeverity() == null ? null : after.getMinSeverity().toString())) {
            sb.append("minSeverity ").append(after.getMinSeverity()).append("; ");
        }
        if (!equalsNullable(
                before.getThrottleSeconds() == null ? null : before.getThrottleSeconds().toString(),
                after.getThrottleSeconds() == null ? null : after.getThrottleSeconds().toString())) {
            sb.append("throttle ").append(after.getThrottleSeconds()).append("s; ");
        }
        if (!equalsNullable(
                before.getEnabled() == null ? null : before.getEnabled().toString(),
                after.getEnabled() == null ? null : after.getEnabled().toString())) {
            sb.append("enabled ").append(after.getEnabled()).append("; ");
        }
        return sb.length() == 0 ? "(no changes detected)" : sb.toString();
    }

    private boolean equalsNullable(String a, String b) {
        if (a == null) return b == null;
        return a.equals(b);
    }
}