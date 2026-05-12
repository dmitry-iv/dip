package com.example.securitycourse.service;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.domain.Role;
import com.example.securitycourse.dto.UserCreateRequest;
import com.example.securitycourse.dto.UserResponse;
import com.example.securitycourse.dto.UserUpdateRequest;
import com.example.securitycourse.repository.RoleRepository;
import com.example.securitycourse.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final AuditService auditService;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       PasswordPolicyService passwordPolicyService,
                       AuditService auditService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.auditService = auditService;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Page<UserResponse> list(int page, int size) {
        return userRepository.findAll(PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")))
                .map(this::toResponse);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public UserResponse create(UserCreateRequest req, HttpServletRequest http) {
        if (userRepository.existsByUsernameIgnoreCase(req.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }
        if (req.getEmail() != null && !req.getEmail().isBlank()
                && userRepository.existsByEmailIgnoreCase(req.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }
        passwordPolicyService.validateOrThrow(req.getPassword());

        AppUser user = new AppUser();
        user.setUsername(req.getUsername().trim());
        user.setEmail(req.getEmail() == null ? null : req.getEmail().trim());
        user.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        user.setEnabled(true);

        if (req.getSource() != null) {
            user.setSource(AppUser.Source.valueOf(req.getSource()));
        } else {
            user.setSource(AppUser.Source.LOCAL);
        }
        user.setExternalId(req.getExternalId());
        user.setExpiresAt(req.getExpiresAt());

        user.setRoles(resolveRolesOrDefault(req.getRoles()));
        userRepository.save(user);

        auditService.logCurrent(http, AuditActions.USER_CREATED, AuditResults.SUCCESS,
                "User", user.getId().toString(),
                "Created user " + user.getUsername() + " (source=" + user.getSource() + ")");
        return toResponse(user);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public UserResponse update(UUID id, UserUpdateRequest req, HttpServletRequest http) {
        AppUser user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (req.getUsername() != null && !req.getUsername().isBlank()
                && !req.getUsername().equalsIgnoreCase(user.getUsername())) {
            if (userRepository.existsByUsernameIgnoreCase(req.getUsername())) {
                throw new IllegalArgumentException("Username already exists");
            }
            user.setUsername(req.getUsername().trim());
        }

        if (req.getEmail() != null && !req.getEmail().equalsIgnoreCase(user.getEmail())) {
            if (!req.getEmail().isBlank() && userRepository.existsByEmailIgnoreCase(req.getEmail())) {
                throw new IllegalArgumentException("Email already exists");
            }
            user.setEmail(req.getEmail().isBlank() ? null : req.getEmail().trim());
        }

        if (req.getEnabled() != null) {
            boolean was = user.isEnabled();
            user.setEnabled(req.getEnabled());
            if (was && !req.getEnabled()) {
                auditService.logCurrent(http, AuditActions.USER_DISABLED, AuditResults.SUCCESS,
                        "User", user.getId().toString(), "Disabled");
            } else if (!was && req.getEnabled()) {
                auditService.logCurrent(http, AuditActions.USER_ENABLED, AuditResults.SUCCESS,
                        "User", user.getId().toString(), "Enabled");
            }
        }

        if (req.getRoles() != null) {
            user.setRoles(resolveRolesOrDefault(req.getRoles()));
            auditService.logCurrent(http, AuditActions.ROLES_CHANGED, AuditResults.SUCCESS,
                    "User", user.getId().toString(), "Roles set to " + rolesString(user));
        }

        if (req.getSource() != null) {
            user.setSource(AppUser.Source.valueOf(req.getSource()));
        }
        if (req.getExpiresAt() != null) {
            user.setExpiresAt(req.getExpiresAt());
        }

        userRepository.save(user);
        auditService.logCurrent(http, AuditActions.USER_UPDATED, AuditResults.SUCCESS,
                "User", user.getId().toString(), "Updated user " + user.getUsername());
        return toResponse(user);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public void delete(UUID id, HttpServletRequest http) {
        AppUser user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        userRepository.delete(user);
        auditService.logCurrent(http, AuditActions.USER_DELETED, AuditResults.SUCCESS,
                "User", id.toString(), "Deleted user " + user.getUsername());
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public void lock(UUID id, HttpServletRequest http) {
        AppUser user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setLockUntil(Instant.now().plusSeconds(15 * 60L));
        userRepository.save(user);
        auditService.logCurrent(http, AuditActions.USER_LOCKED, AuditResults.SUCCESS,
                "User", id.toString(), "Locked until " + user.getLockUntil());
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public void unlock(UUID id, HttpServletRequest http) {
        AppUser user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setLockUntil(null);
        user.setFailedLoginAttempts(0);
        userRepository.save(user);
        auditService.logCurrent(http, AuditActions.USER_UNLOCKED, AuditResults.SUCCESS,
                "User", id.toString(), "Unlocked");
    }

    @Transactional
    public void changePassword(UUID userId, String currentPasswordRaw, String newPasswordRaw, HttpServletRequest http) {
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (currentPasswordRaw == null || !passwordEncoder.matches(currentPasswordRaw, user.getPasswordHash())) {
            auditService.logCurrent(http, AuditActions.PASSWORD_CHANGED, AuditResults.FAIL,
                    "User", userId.toString(), "Wrong current password");
            throw new IllegalArgumentException("CURRENT_PASSWORD_INVALID");
        }
        passwordPolicyService.validateOrThrow(newPasswordRaw);

        user.setPasswordHash(passwordEncoder.encode(newPasswordRaw));
        userRepository.save(user);
        auditService.logCurrent(http, AuditActions.PASSWORD_CHANGED, AuditResults.SUCCESS,
                "User", userId.toString(), "Password changed");
    }

    @PreAuthorize("hasRole('ADMIN')")
    public AppUser getById(UUID id) {
        return userRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    private UserResponse toResponse(AppUser u) {
        UserResponse dto = new UserResponse();
        dto.setId(u.getId());
        dto.setUsername(u.getUsername());
        dto.setEmail(u.getEmail());
        dto.setEnabled(u.isEnabled());
        dto.setFailedLoginAttempts(u.getFailedLoginAttempts());
        dto.setLockUntil(u.getLockUntil());
        dto.setRoles(u.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));
        dto.setSource(u.getSource() == null ? null : u.getSource().name());
        dto.setExpiresAt(u.getExpiresAt());
        dto.setTotpEnabled(u.isTotpEnabled());
        return dto;
    }

    private Set<Role> resolveRolesOrDefault(Set<String> names) {
        Set<String> normalized = (names == null || names.isEmpty()) ? Set.of("USER") : names;
        Set<Role> roles = new HashSet<>();
        for (String n : normalized) {
            String name = n == null ? "" : n.trim();
            if (name.isBlank()) continue;
            if (name.startsWith("ROLE_")) name = name.substring("ROLE_".length());
            final String roleName = name;
            roles.add(roleRepository.findByName(roleName)
                    .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleName)));
        }
        if (roles.isEmpty()) {
            roles.add(roleRepository.findByName("USER")
                    .orElseThrow(() -> new IllegalStateException("Role USER not found")));
        }
        return roles;
    }

    private String rolesString(AppUser u) {
        return u.getRoles().stream().map(Role::getName).sorted().collect(Collectors.joining(","));
    }
}