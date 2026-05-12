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
import org.springframework.beans.factory.annotation.Value;
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
    private final TwoFactorService twoFactorService;

    @Value("${app.security.mfa.pending-ttl-seconds:300}")
    private long mfaPendingTtl;

    public AuthService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       PasswordPolicyService passwordPolicyService,
                       JwtService jwtService,
                       AuditService auditService,
                       TwoFactorService twoFactorService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.jwtService = jwtService;
        this.auditService = auditService;
        this.twoFactorService = twoFactorService;
    }

    @Transactional
    public void register(RegisterRequest req, HttpServletRequest http) {
        if (userRepository.existsByUsernameIgnoreCase(req.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }
        if (req.getEmail() != null && !req.getEmail().isBlank()
                && userRepository.existsByEmailIgnoreCase(req.getEmail())) {
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
        user.setSource(AppUser.Source.LOCAL);
        user.setRoles(Set.of(userRole));

        userRepository.save(user);

        auditService.log(http, user.getId(), user.getUsername(), "ROLE_USER",
                AuditActions.REGISTER, AuditResults.SUCCESS,
                "User", user.getId().toString(), "Self-registration");
    }

    @Transactional
    public AuthResponse login(LoginRequest req, HttpServletRequest http) {
        String login = req.getLogin().trim();
        AppUser user = userRepository.findByUsernameOrEmailIgnoreCase(login)
                .orElseThrow(() -> {
                    auditService.log(http, null, login, null,
                            AuditActions.LOGIN_FAILURE, AuditResults.FAIL,
                            null, null, "Unknown user");
                    return new IllegalArgumentException("Invalid credentials");
                });

        Instant now = Instant.now();

        if (!user.isEnabled()) {
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.LOGIN_FAILURE, AuditResults.FAIL,
                    null, null, "Account disabled");
            throw new IllegalArgumentException("Account disabled");
        }
        if (user.isLockedNow(now)) {
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.LOGIN_FAILURE, AuditResults.FAIL,
                    null, null, "Account locked until " + user.getLockUntil());
            throw new IllegalArgumentException("Account locked");
        }
        if (user.isExpired(now)) {
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.LOGIN_FAILURE, AuditResults.FAIL,
                    null, null, "Account expired");
            throw new IllegalArgumentException("Account expired");
        }

        if (!passwordEncoder.matches(req.getPassword(), user.getPasswordHash())) {
            onFailedLoginInternal(user, now);
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.LOGIN_FAILURE, AuditResults.FAIL,
                    null, null, "Bad password");
            throw new IllegalArgumentException("Invalid credentials");
        }

        if (user.requiresMfa()) {
            String pending = jwtService.issueMfaPendingToken(user.getId(), user.getUsername(), mfaPendingTtl);
            auditService.log(http, user.getId(), user.getUsername(), null,
                    AuditActions.MFA_CHALLENGE_ISSUED, AuditResults.SUCCESS,
                    null, null, "MFA challenge issued");
            return AuthResponse.mfaPending(pending, mfaPendingTtl);
        }

        return issueFullToken(user, http, "Direct login (no MFA required)");
    }

    @Transactional
    public AuthResponse verifyMfa(String mfaPendingToken, String code, HttpServletRequest http) {
        UUID userId = jwtService.parseMfaPendingTokenUserId(mfaPendingToken);
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!twoFactorService.verify(user, code, http)) {
            onFailedLoginInternal(user, Instant.now());
            throw new IllegalArgumentException("Invalid MFA code");
        }
        return issueFullToken(user, http, "Login with MFA");
    }

    private AuthResponse issueFullToken(AppUser user, HttpServletRequest http, String details) {
        onSuccessfulLoginInternal(user, http);

        List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
        String jwt = jwtService.issueToken(user.getId(), user.getUsername(), roles);

        auditService.log(http, user.getId(), user.getUsername(), rolesAsAuthoritiesString(roles),
                AuditActions.LOGIN_SUCCESS, AuditResults.SUCCESS,
                null, null, details);

        return AuthResponse.full(jwt, jwtService.getTtlSeconds());
    }

    @Transactional
    public void onFailedLogin(String login) {
        if (login == null || login.isBlank()) return;
        userRepository.findByUsernameOrEmailIgnoreCase(login.trim())
                .ifPresent(u -> onFailedLoginInternal(u, Instant.now()));
    }

    @Transactional
    public void onSuccessfulLogin(String login, HttpServletRequest http) {
        if (login == null || login.isBlank()) return;
        userRepository.findByUsernameOrEmailIgnoreCase(login.trim())
                .ifPresent(u -> onSuccessfulLoginInternal(u, http));
    }

    private void onFailedLoginInternal(AppUser user, Instant now) {
        int next = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(next);
        if (next >= MAX_FAILED_ATTEMPTS) {
            user.setLockUntil(now.plus(LOCK_DURATION));
        }
        userRepository.save(user);
    }

    private void onSuccessfulLoginInternal(AppUser user, HttpServletRequest http) {
        user.setFailedLoginAttempts(0);
        user.setLockUntil(null);
        user.setLastLoginAt(Instant.now());
        if (http != null) {
            user.setLastLoginIp(extractIp(http));
        }
        userRepository.save(user);
    }

    private String rolesAsAuthoritiesString(List<String> roles) {
        return roles.stream()
                .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                .collect(Collectors.joining(","));
    }

    private String extractIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}