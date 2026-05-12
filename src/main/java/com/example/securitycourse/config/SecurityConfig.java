package com.example.securitycourse.config;

import com.example.securitycourse.security.CustomUserDetailsService;
import com.example.securitycourse.security.JwtAuthenticationFilter;
import com.example.securitycourse.security.MfaEnforcementFilter;
import com.example.securitycourse.security.WebAuthHandlers;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Двухконтурная конфигурация:
 *  - apiChain (Order 1, /api/**) — stateless, JWT-фильтр, отдаёт 401 для неавторизованных.
 *  - webChain (Order 2, остальное) — form login, Thymeleaf UI.
 *
 * Безопасные HTTP-заголовки (CSP, HSTS, X-Frame, Referrer-Policy) — OWASP A05.
 * Argon2id вместо BCrypt — современный KDF (победитель PHC).
 *
 * MfaEnforcementFilter — после авторизации редиректит EXTERNAL-пользователей
 * без настроенной 2FA на страницу её обязательной настройки.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            CustomUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        DaoAuthenticationProvider local = new DaoAuthenticationProvider(userDetailsService);
        local.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(local);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain apiChain(HttpSecurity http,
                                        JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                .securityMatcher("/api/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/webjars/**", "/fonts/**", "/favicon.ico").permitAll()
                        .requestMatchers("/login", "/2fa/**").permitAll()
                        .requestMatchers("/profile/**").authenticated()
                        .requestMatchers("/me/**").authenticated()
                        .requestMatchers("/soc/**").hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/audit/**").hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/incidents/**").hasAnyRole("MANAGER", "ADMIN")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .httpBasic(Customizer.withDefaults());

        applySecurityHeaders(http);
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain webChain(HttpSecurity http,
                                        WebAuthHandlers handlers,
                                        MfaEnforcementFilter mfaEnforcementFilter) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/webjars/**", "/fonts/**", "/favicon.ico").permitAll()
                        .requestMatchers("/login", "/2fa/**").permitAll()
                        .requestMatchers("/profile/**").authenticated()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/audit/**").hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/incidents/**").hasAnyRole("MANAGER", "ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(handlers.loginSuccessHandler())
                        .failureHandler(handlers.loginFailureHandler())
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(handlers.logoutSuccessHandler())
                )
                .exceptionHandling(ex -> ex.accessDeniedHandler(handlers.accessDeniedHandler()))
                // MFA enforcement — после авторизации, перед обработкой запроса
                .addFilterAfter(mfaEnforcementFilter, AuthorizationFilter.class);

        applySecurityHeaders(http);
        return http.build();
    }

    private void applySecurityHeaders(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'self'; "
                                + "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                + "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                + "font-src 'self' https://cdn.jsdelivr.net data:; "
                                + "img-src 'self' data:; "
                                + "frame-ancestors 'none'; "
                                + "form-action 'self'"))
                .httpStrictTransportSecurity(hsts -> hsts
                        .maxAgeInSeconds(31_536_000)
                        .includeSubDomains(true))
                .frameOptions(f -> f.deny())
                .contentTypeOptions(Customizer.withDefaults())
                .referrerPolicy(r -> r.policy(
                        ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .permissionsPolicyHeader(p -> p.policy(
                        "camera=(), microphone=(), geolocation=(), payment=()"))
        );
    }
}