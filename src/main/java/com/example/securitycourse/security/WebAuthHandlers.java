package com.example.securitycourse.security;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.service.AuditService;
import com.example.securitycourse.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class WebAuthHandlers {

    private final AuthService authService;
    private final AuditService auditService;

    public WebAuthHandlers(AuthService authService, AuditService auditService) {
        this.authService = authService;
        this.auditService = auditService;
    }

    public AuthenticationSuccessHandler loginSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
            authService.onSuccessfulLogin(authentication.getName());
            auditService.logCurrent(request,
                    AuditActions.LOGIN_SUCCESS.name(),
                    AuditResults.SUCCESS.name(),
                    null, null, "Form login");
            response.sendRedirect("/");
        };
    }

    public AuthenticationFailureHandler loginFailureHandler() {
        return (HttpServletRequest request, HttpServletResponse response,
                org.springframework.security.core.AuthenticationException exception) -> {
            String login = request.getParameter("username");

            // Если уже заблокирован/отключён — не увеличиваем счётчик попыток.
            boolean locked = (exception instanceof LockedException);
            boolean disabled = (exception instanceof DisabledException);

            if (!locked && !disabled && login != null && !login.isBlank()) {
                authService.onFailedLogin(login);
            }

            auditService.log(request, null, login, null,
                    AuditActions.LOGIN_FAILURE.name(),
                    AuditResults.FAIL.name(),
                    null, null, exception.getMessage());

            if (locked) {
                response.sendRedirect("/login?locked");
            } else if (disabled) {
                response.sendRedirect("/login?disabled");
            } else {
                response.sendRedirect("/login?error");
            }
        };
    }

    public LogoutSuccessHandler logoutSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
            auditService.logCurrent(request,
                    AuditActions.LOGOUT.name(),
                    AuditResults.SUCCESS.name(),
                    null, null, "Logout");
            response.sendRedirect("/login?logout");
        };
    }

    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            auditService.logCurrent(request,
                    AuditActions.ACCESS_DENIED.name(),
                    AuditResults.FAIL.name(),
                    null, null, request.getRequestURI());
            response.sendRedirect("/403");
        };
    }
}