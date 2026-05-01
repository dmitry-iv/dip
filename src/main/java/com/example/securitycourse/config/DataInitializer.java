package com.example.securitycourse.config;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.domain.Role;
import com.example.securitycourse.repository.RoleRepository;
import com.example.securitycourse.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
@ConditionalOnProperty(name = "app.bootstrap.admin.enabled", havingValue = "true", matchIfMissing = true)
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    private final String adminUsername;
    private final String adminPassword;
    private final String adminEmail;

    public DataInitializer(UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder,
                           @Value("${app.bootstrap.admin.username:admin}") String adminUsername,
                           @Value("${app.bootstrap.admin.password:Admin123!}") String adminPassword,
                           @Value("${app.bootstrap.admin.email:admin@example.com}") String adminEmail) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.adminEmail = adminEmail;
    }

    @Override
    public void run(String... args) {
        // Create default admin for demo/dev only
        if (userRepository.existsByUsernameIgnoreCase(adminUsername)) {
            return;
        }

        // Ensure roles exist (Flyway usually seeds them, but we also self-heal on a fresh/dirty DB)
        Role admin = roleRepository.findByName("ADMIN")
                .orElseGet(() -> {
                    Role r = new Role();
                    r.setId(java.util.UUID.randomUUID());
                    r.setName("ADMIN");
                    return roleRepository.save(r);
                });

        Role manager = roleRepository.findByName("MANAGER")
                .orElseGet(() -> {
                    Role r = new Role();
                    r.setId(java.util.UUID.randomUUID());
                    r.setName("MANAGER");
                    return roleRepository.save(r);
                });

        Role user = roleRepository.findByName("USER")
                .orElseGet(() -> {
                    Role r = new Role();
                    r.setId(java.util.UUID.randomUUID());
                    r.setName("USER");
                    return roleRepository.save(r);
                });

        Set<Role> roles = new HashSet<>();
        roles.add(admin);
        roles.add(manager);
        roles.add(user);

        AppUser u = new AppUser();
        u.setUsername(adminUsername);
        u.setEmail(adminEmail);
        u.setEnabled(true);
        u.setPasswordHash(passwordEncoder.encode(adminPassword));
        u.setRoles(roles);

        userRepository.save(u);
    }
}
