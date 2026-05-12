package com.example.securitycourse.controller.web;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.repository.AuditLogRepository;
import com.example.securitycourse.repository.UserRepository;
import com.example.securitycourse.security.AuthPrincipal;
import com.example.securitycourse.service.HashChainService;
import com.example.securitycourse.service.IncidentService;
import com.example.securitycourse.service.ReportJsonHelper;
import com.example.securitycourse.service.ReportService;
import com.example.securitycourse.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

@Controller
public class WebController {

    private static final Logger log = LoggerFactory.getLogger(WebController.class);

    private final UserRepository userRepository;
    private final UserService userService;
    private final IncidentService incidentService;
    private final AuditLogRepository auditLogRepository;
    private final HashChainService hashChainService;
    private final ReportService reportService;
    private final ReportJsonHelper jsonHelper;

    public WebController(UserRepository userRepository,
                         UserService userService,
                         IncidentService incidentService,
                         AuditLogRepository auditLogRepository,
                         HashChainService hashChainService,
                         ReportService reportService,
                         ReportJsonHelper jsonHelper) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.incidentService = incidentService;
        this.auditLogRepository = auditLogRepository;
        this.hashChainService = hashChainService;
        this.reportService = reportService;
        this.jsonHelper = jsonHelper;
    }

    /**
     * Главная страница — редиректит на нужную в зависимости от роли:
     *   ADMIN  → /  (полный дашборд, рендерится этим же методом)
     *   MANAGER → /soc (рабочая SOC-панель)
     *   USER   → /me  (личная активность)
     */
    @GetMapping("/")
    public String home(Model model, Authentication authentication) {
        boolean isAdmin = hasRole(authentication, "ROLE_ADMIN");
        boolean isManager = hasRole(authentication, "ROLE_MANAGER");

        // Простому пользователю — на свою страницу
        if (!isAdmin && !isManager) {
            return "redirect:/me";
        }
        // Аналитику без админских прав — на SOC-панель
        if (!isAdmin && isManager) {
            return "redirect:/soc";
        }

        // ADMIN видит общий дашборд
        return renderDashboard(model, authentication);
    }

    /** Полный дашборд — для ADMIN. */
    private String renderDashboard(Model model, Authentication authentication) {
        model.addAttribute("username", authentication.getName());

        try {
            IncidentService.DashboardStats stats = incidentService.stats();
            model.addAttribute("openIncidents", stats.openIncidents());
            model.addAttribute("inProgress", stats.inProgress());
            model.addAttribute("highSeverity24h", stats.highSeverityLast24h());
            model.addAttribute("totalIncidents", stats.total());
        } catch (Exception e) {
            log.warn("Failed to load incident stats: {}", e.getMessage());
            model.addAttribute("openIncidents", 0L);
            model.addAttribute("inProgress", 0L);
            model.addAttribute("highSeverity24h", 0L);
            model.addAttribute("totalIncidents", 0L);
        }

        long auditCount = 0L;
        try { auditCount = auditLogRepository.count(); } catch (Exception ignored) {}

        try {
            HashChainService.IntegrityCheckResult report = hashChainService.verifyChain();
            model.addAttribute("integrityValid", report.valid());
            model.addAttribute("integrityChecked", report.recordsChecked());
            model.addAttribute("integrityMessage", report.message());
            model.addAttribute("integrityFailureId", report.firstFailureId());
        } catch (Exception e) {
            log.warn("Failed to verify audit chain integrity: {}", e.getMessage());
            model.addAttribute("integrityValid", true);
            model.addAttribute("integrityChecked", auditCount);
            model.addAttribute("integrityMessage", "проверка пропущена");
            model.addAttribute("integrityFailureId", null);
        }
        model.addAttribute("auditCount", auditCount);

        try {
            ReportService.ActivityChartData chart = reportService.activityLast24h();
            model.addAttribute("chartLabelsJson", jsonHelper.anyToJson(chart.labels()));
            model.addAttribute("chartAuditJson", jsonHelper.anyToJson(chart.auditPerHour()));
            model.addAttribute("chartIncidentsJson", jsonHelper.anyToJson(chart.incidentPerHour()));
        } catch (Exception e) {
            log.warn("Failed to load chart data: {}", e.getMessage());
            model.addAttribute("chartLabelsJson", "[]");
            model.addAttribute("chartAuditJson", "[]");
            model.addAttribute("chartIncidentsJson", "[]");
        }

        return "index";
    }

    private boolean hasRole(Authentication auth, String role) {
        if (auth == null || auth.getAuthorities() == null) return false;
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role::equals);
    }

    @GetMapping("/login")
    public String login() { return "login"; }

    @GetMapping("/profile")
    public String profile(Model model, Authentication authentication) {
        Object p = authentication.getPrincipal();
        if (p instanceof AuthPrincipal ap) {
            AppUser user = userRepository.findById(ap.getUserId()).orElse(null);
            model.addAttribute("user", user);
        }
        if (!model.containsAttribute("passwordForm")) {
            model.addAttribute("passwordForm", new ChangePasswordForm());
        }
        return "profile";
    }

    @PostMapping("/profile/password")
    public String changePassword(@ModelAttribute("passwordForm") ChangePasswordForm form,
                                 BindingResult binding,
                                 Authentication authentication,
                                 HttpServletRequest request,
                                 RedirectAttributes ra) {
        Object p = authentication.getPrincipal();
        if (!(p instanceof AuthPrincipal ap)) return "redirect:/login";

        if (isBlank(form.getCurrentPassword())) binding.rejectValue("currentPassword", "required", "Введите текущий пароль");
        if (isBlank(form.getNewPassword())) binding.rejectValue("newPassword", "required", "Введите новый пароль");
        if (isBlank(form.getConfirmPassword())) binding.rejectValue("confirmPassword", "required", "Подтвердите новый пароль");
        if (!isBlank(form.getNewPassword()) && !isBlank(form.getConfirmPassword())
                && !form.getNewPassword().equals(form.getConfirmPassword())) {
            binding.rejectValue("confirmPassword", "mismatch", "Пароли не совпадают");
        }

        if (binding.hasErrors()) {
            ra.addFlashAttribute("org.springframework.validation.BindingResult.passwordForm", binding);
            ra.addFlashAttribute("passwordForm", form);
            return "redirect:/profile";
        }

        try {
            userService.changePassword(ap.getUserId(), form.getCurrentPassword(), form.getNewPassword(), request);
            ra.addFlashAttribute("passwordSuccess", "Пароль успешно изменён");
        } catch (IllegalArgumentException ex) {
            if ("CURRENT_PASSWORD_INVALID".equals(ex.getMessage())) {
                binding.rejectValue("currentPassword", "invalid", "Текущий пароль неверный");
            } else {
                binding.rejectValue("newPassword", "invalid", ex.getMessage());
            }
            ra.addFlashAttribute("org.springframework.validation.BindingResult.passwordForm", binding);
            ra.addFlashAttribute("passwordForm", form);
        }
        return "redirect:/profile";
    }

    private static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }

    public static class ChangePasswordForm {
        @NotBlank private String currentPassword;
        @NotBlank private String newPassword;
        @NotBlank private String confirmPassword;
        public String getCurrentPassword() { return currentPassword; }
        public void setCurrentPassword(String currentPassword) { this.currentPassword = currentPassword; }
        public String getNewPassword() { return newPassword; }
        public void setNewPassword(String newPassword) { this.newPassword = newPassword; }
        public String getConfirmPassword() { return confirmPassword; }
        public void setConfirmPassword(String confirmPassword) { this.confirmPassword = confirmPassword; }
    }

    @GetMapping("/report")
    public String report(Model model) {
        try {
            ReportService.ReportSummary summary = reportService.summary();
            Map<String, Long> categoryDist = reportService.categoryDistribution24h();
            long[] severityDist = reportService.severityDistribution24h();

            model.addAttribute("summary", summary);
            model.addAttribute("categoryDistribution", categoryDist);
            model.addAttribute("categoryDistributionJson", jsonHelper.anyToJson(categoryDist));
            model.addAttribute("severityDistribution", severityDist);
            model.addAttribute("severityDistributionJson", jsonHelper.anyToJson(severityDist));
            model.addAttribute("topIps", reportService.topIpsLast24h());
            model.addAttribute("topUsers", reportService.topUsersLast24h());
            model.addAttribute("topRules", reportService.topRulesAllTime());
            model.addAttribute("incidentStatuses", reportService.incidentStatusDistribution());
        } catch (Exception e) {
            log.error("Failed to build report", e);
            model.addAttribute("reportError", e.getMessage());
        }
        return "report";
    }

    @GetMapping("/report/export.csv")
    public void exportCsv(HttpServletResponse response) throws IOException {
        String filename = "corpsec-report-" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmm")) +
                ".csv";
        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

        try (PrintWriter w = response.getWriter()) {
            w.write('\uFEFF');

            ReportService.ReportSummary summary = reportService.summary();
            w.println("Сводный отчёт CorpSec," + LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")));
            w.println();
            w.println("Метрика;Значение");
            w.println("Всего событий аудита;" + summary.totalAudit());
            w.println("Всего инцидентов;" + summary.totalIncidents());
            w.println("Инцидентов за 24ч;" + summary.incidents24h());
            w.println("High/Critical 24ч;" + summary.highSeverity24h());
            w.println();

            w.println("=== Распределение событий по категориям (24ч) ===");
            w.println("Категория;Событий");
            for (Map.Entry<String, Long> e : reportService.categoryDistribution24h().entrySet()) {
                w.println(e.getKey() + ";" + e.getValue());
            }
            w.println();

            w.println("=== Распределение по severity (24ч) ===");
            w.println("Severity;Событий");
            long[] sev = reportService.severityDistribution24h();
            String[] names = {"1 Info", "2 Low", "3 Medium", "4 High", "5 Critical"};
            for (int i = 0; i < 5; i++) w.println(names[i] + ";" + sev[i]);
            w.println();

            w.println("=== Топ-10 IP по активности (24ч) ===");
            w.println("IP-адрес;Событий");
            for (ReportService.TopItem it : reportService.topIpsLast24h()) {
                w.println(it.name() + ";" + it.count());
            }
            w.println();

            w.println("=== Топ-10 пользователей (24ч) ===");
            w.println("Пользователь;Событий");
            for (ReportService.TopItem it : reportService.topUsersLast24h()) {
                w.println(it.name() + ";" + it.count());
            }
            w.println();

            w.println("=== Топ инцидентов по правилам ===");
            w.println("Правило;Случаев");
            for (ReportService.TopItem it : reportService.topRulesAllTime()) {
                w.println(it.name() + ";" + it.count());
            }
            w.println();

            w.println("=== Распределение инцидентов по статусу ===");
            w.println("Статус;Случаев");
            for (Map.Entry<String, Long> e : reportService.incidentStatusDistribution().entrySet()) {
                w.println(e.getKey() + ";" + e.getValue());
            }
        }
    }

    @GetMapping("/report/export.html")
    public String exportPrintable(Model model) {
        try {
            ReportService.ReportSummary summary = reportService.summary();
            model.addAttribute("summary", summary);
            model.addAttribute("categoryDistribution", reportService.categoryDistribution24h());
            model.addAttribute("severityDistribution", reportService.severityDistribution24h());
            model.addAttribute("topIps", reportService.topIpsLast24h());
            model.addAttribute("topUsers", reportService.topUsersLast24h());
            model.addAttribute("topRules", reportService.topRulesAllTime());
            model.addAttribute("incidentStatuses", reportService.incidentStatusDistribution());
            model.addAttribute("generatedAt",
                    LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")));
        } catch (Exception e) {
            log.error("Failed to build printable report", e);
        }
        return "report-printable";
    }

    @GetMapping("/403")
    public String forbidden() { return "error/403"; }
}