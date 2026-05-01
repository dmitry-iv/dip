package com.example.securitycourse.security;

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
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, CustomUserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring("Bearer ".length()).trim();
        try {
            Claims claims = jwtService.parseClaims(token);
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

            // We don't re-fetch from DB for every request; but we do want to enforce lock/enabled.
            // So we load UserDetails and take enabled/lock state.
            AuthPrincipal details = (AuthPrincipal) userDetailsService.loadUserByUsername(username);
            if (!details.isEnabled() || !details.isAccountNonLocked()) {
                filterChain.doFilter(request, response);
                return;
            }

            AuthPrincipal principal = new AuthPrincipal(
                    userId != null ? userId : details.getUserId(),
                    details.getUsername(),
                    details.getPassword(),
                    details.isEnabled(),
                    details.isAccountNonLocked(),
                    authorities.isEmpty() ? details.getAuthorities() : authorities
            );

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (Exception ignored) {
            // invalid token -> ignore, let security handle
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/");
    }
}
