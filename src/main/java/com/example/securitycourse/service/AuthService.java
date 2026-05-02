package com.example.securitycourse.service;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.domain.Role;
import com.example.securitycourse.dto.AuthResponse;
import com.example.securitycourse.dto.LoginRequest;
import com.example.securitycourse.dto.RegisterRequest;
import com.example.securitycourse.repository.RoleRepository;
import com.example.securitycourse.repository.UserRepository;
import com.example.securitycourse.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final JwtService jwtService;
    private final AuditService auditService;
    private final TotpService totpService;

    public AuthService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       PasswordPolicyService passwordPolicyService,
                       JwtService jwtService,
                       AuditService auditService,
                       TotpService totpService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.jwtService = jwtService;
        this.auditService = auditService;
        this.totpService = totpService;
    }

    @Transactional
    public void register(RegisterRequest req, HttpServletRequest http) {
        if (userRepository.existsByUsernameIgnoreCase(req.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }
        if (req.getEmail() != null && !req.getEmail().isBlank() && userRepository.existsByEmailIgnoreCase(req.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }
        passwordPolicyService.validateOrThrow(req.getPassword());

        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException("Role USER not found"));

        AppUser user = new AppUser();
        user.setUsername(req.getUsername().trim());
        user.setEmail(req.getEmail() == null ? null : req.getEmail().trim());
        user.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        user.setEnabled(true);
        user.setRoles(Set.of(userRole));

        userRepository.save(user);

        auditService.log(http, user.getId(), user.getUsername(), "ROLE_USER",
                AuditActions.REGISTER.name(), AuditResults.SUCCESS.name(),
                "User", user.getId().toString(), "Registration");
    }

    @Transactional
    public AuthResponse login(LoginRequest req, HttpServletRequest http) {
        String login = req.getLogin().trim();
        AppUser user = userRepository.findByUsernameOrEmailIgnoreCase(login)
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        Instant now = Instant.now();
        if (!user.isEnabled()) {
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.LOGIN_FAILURE.name(), AuditResults.FAIL.name(),
                    null, null, "Account disabled");
            throw new IllegalArgumentException("Account disabled");
        }
        if (user.isLockedNow(now)) {
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.LOGIN_FAILURE.name(), AuditResults.FAIL.name(),
                    null, null, "Account locked until " + user.getLockUntil());
            throw new IllegalArgumentException("Account locked");
        }

        if (!passwordEncoder.matches(req.getPassword(), user.getPasswordHash())) {
            onFailedLoginInternal(user, now);
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.LOGIN_FAILURE.name(), AuditResults.FAIL.name(),
                    null, null, "Bad password");
            throw new IllegalArgumentException("Invalid credentials");
        }

        if (user.isTotpEnabled()) {
            String tempToken = jwtService.issueTwoFactorToken(user.getId(), user.getUsername());
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.LOGIN_SUCCESS.name(), AuditResults.SUCCESS.name(),
                    null, null, "First factor passed, 2FA required");
            return new AuthResponse(true, tempToken, jwtService.getTtlSeconds());
        }

        onSuccessfulLoginInternal(user);
        List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
        String jwt = jwtService.issueToken(user.getId(), user.getUsername(), roles);

        auditService.log(http, user.getId(), user.getUsername(), rolesAsAuthoritiesString(roles),
                AuditActions.LOGIN_SUCCESS.name(), AuditResults.SUCCESS.name(),
                null, null, "JWT login");

        return new AuthResponse(jwt, jwtService.getTtlSeconds());
    }

    @Transactional
    public AuthResponse verifyTwoFactor(String twoFactorToken, String code, boolean isBackupCode, HttpServletRequest http) {
        UUID userId = jwtService.validateTwoFactorToken(twoFactorToken);
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        boolean valid;
        if (isBackupCode) {
            valid = totpService.useBackupCode(user, code);
            if (valid) {
                userRepository.save(user);
            }
        } else {
            valid = totpService.verifyCode(user.getTotpSecret(), code);
        }

        if (!valid) {
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.LOGIN_FAILURE.name(), AuditResults.FAIL.name(),
                    null, null, "2FA code invalid");
            throw new IllegalArgumentException("Invalid verification code");
        }

        onSuccessfulLoginInternal(user);
        List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
        String jwt = jwtService.issueToken(user.getId(), user.getUsername(), roles);

        auditService.log(http, user.getId(), user.getUsername(), rolesAsAuthoritiesString(roles),
                AuditActions.LOGIN_SUCCESS.name(), AuditResults.SUCCESS.name(),
                null, null, "2FA verification successful");

        return new AuthResponse(jwt, jwtService.getTtlSeconds());
    }

    @Transactional
    public void onFailedLogin(String login) {
        if (login == null || login.isBlank()) {
            return;
        }
        userRepository.findByUsernameOrEmailIgnoreCase(login.trim())
                .ifPresent(u -> onFailedLoginInternal(u, Instant.now()));
    }

    @Transactional
    public void onSuccessfulLogin(String login) {
        if (login == null || login.isBlank()) {
            return;
        }
        userRepository.findByUsernameOrEmailIgnoreCase(login.trim())
                .ifPresent(this::onSuccessfulLoginInternal);
    }

    private void onFailedLoginInternal(AppUser user, Instant now) {
        int next = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(next);
        if (next >= MAX_FAILED_ATTEMPTS) {
            user.setLockUntil(now.plus(LOCK_DURATION));
        }
        userRepository.save(user);
    }

    private void onSuccessfulLoginInternal(AppUser user) {
        user.setFailedLoginAttempts(0);
        user.setLockUntil(null);
        userRepository.save(user);
    }

    private String rolesAsAuthoritiesString(List<String> roles) {
        return roles.stream()
                .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                .collect(Collectors.joining(","));
    }
}