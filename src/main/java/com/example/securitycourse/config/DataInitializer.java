package com.example.securitycourse.config;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.domain.Role;
import com.example.securitycourse.repository.RoleRepository;
import com.example.securitycourse.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Component
@ConditionalOnProperty(name = "app.bootstrap.admin.enabled", havingValue = "true", matchIfMissing = true)
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

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
    @Transactional
    public void run(String... args) {
        ensureRole("USER");
        ensureRole("MANAGER");
        ensureRole("ADMIN");

        if (userRepository.existsByUsernameIgnoreCase(adminUsername)) {
            log.info("Admin '{}' already exists, skipping bootstrap", adminUsername);
            return;
        }

        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByName("ADMIN").orElseThrow());
        roles.add(roleRepository.findByName("MANAGER").orElseThrow());
        roles.add(roleRepository.findByName("USER").orElseThrow());

        AppUser u = new AppUser();
        u.setUsername(adminUsername);
        u.setEmail(adminEmail);
        u.setEnabled(true);
        u.setSource(AppUser.Source.LOCAL);
        u.setPasswordHash(passwordEncoder.encode(adminPassword));
        u.setRoles(roles);
        userRepository.save(u);

        log.info("Bootstrap admin '{}' created", adminUsername);
    }

    private void ensureRole(String name) {
        if (roleRepository.findByName(name).isEmpty()) {
            Role r = new Role();
            r.setName(name);
            roleRepository.save(r);
            log.info("Role '{}' created", name);
        }
    }
}