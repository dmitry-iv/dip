package com.example.securitycourse.security;

import com.example.securitycourse.repository.RevokedTokenRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * JWT-фильтр для /api/**.
 * Дополнительно к проверке подписи:
 *  - отвергает mfa_pending токены (они не дают доступа к API);
 *  - проверяет, что jti не в чёрном списке (logout / revoke);
 *  - подгружает enabled/locked/expired состояние из БД.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final RevokedTokenRepository revokedTokenRepository;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   CustomUserDetailsService userDetailsService,
                                   RevokedTokenRepository revokedTokenRepository) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.revokedTokenRepository = revokedTokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring("Bearer ".length()).trim();
        try {
            Claims claims = jwtService.parseClaims(token);

            // 1) Только access-токены пускаем в API
            String type = claims.get(JwtService.CLAIM_TYPE, String.class);
            if (type != null && !JwtService.TYPE_ACCESS.equals(type)) {
                filterChain.doFilter(request, response);
                return;
            }

            // 2) Проверка чёрного списка jti
            String jtiStr = claims.getId();
            if (jtiStr != null) {
                try {
                    UUID jti = UUID.fromString(jtiStr);
                    if (revokedTokenRepository.existsByJti(jti)) {
                        filterChain.doFilter(request, response);
                        return;
                    }
                } catch (IllegalArgumentException ignore) {
                    // некорректный jti — пропускаем
                }
            }

            String username = claims.getSubject();
            String uidStr = claims.get("uid", String.class);
            UUID userId = uidStr == null ? null : UUID.fromString(uidStr);

            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            if (roles != null) {
                for (String r : roles) {
                    String role = r.startsWith("ROLE_") ? r : "ROLE_" + r;
                    authorities.add(new SimpleGrantedAuthority(role));
                }
            }

            // 3) Подтягиваем актуальное состояние пользователя (enabled/locked/expired)
            AuthPrincipal details = (AuthPrincipal) userDetailsService.loadUserByUsername(username);
            if (!details.isEnabled() || !details.isAccountNonLocked() || !details.isAccountNonExpired()) {
                filterChain.doFilter(request, response);
                return;
            }

            AuthPrincipal principal = new AuthPrincipal(
                    userId != null ? userId : details.getUserId(),
                    details.getUsername(),
                    details.getPassword(),
                    details.isEnabled(),
                    details.isAccountNonLocked(),
                    details.isAccountNonExpired(),
                    authorities.isEmpty() ? details.getAuthorities() : authorities
            );

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (Exception ignored) {
            // невалидный токен → пропускаем, security вернёт 401
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/");
    }
}