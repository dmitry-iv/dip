package com.example.securitycourse.security;

import com.example.securitycourse.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class JwtService {

    private final JwtProperties props;
    private final SecretKey key;

    public JwtService(JwtProperties props) {
        this.props = props;
        byte[] bytes = props.getSecret() == null ? new byte[0] : props.getSecret().getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalArgumentException("app.security.jwt.secret must be at least 32 bytes");
        }
        this.key = Keys.hmacShaKeyFor(bytes);
    }

    /**
     * Создаёт полноценный JWT (access token) с ролями.
     */
    public String issueToken(UUID userId, String username, List<String> roles) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(props.getTtlSeconds());

        return Jwts.builder()
                .subject(username)
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .claim("uid", userId.toString())
                .claim("roles", roles)
                .signWith(key)
                .compact();
    }

    /**
     * Создаёт временный токен для незавершённой аутентификации (2FA).
     * Время жизни фиксировано — 5 минут.
     */
    public String issueTwoFactorToken(UUID userId, String username) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(300); // 5 minutes

        return Jwts.builder()
                .subject(username)
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .claim("uid", userId.toString())
                .claim("twofactor", true) // флаг, что это 2FA-токен
                .signWith(key)
                .compact();
    }

    /**
     * Парсит любой токен и возвращает Claims.
     */
    public Claims parseClaims(String jwt) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    /**
     * Проверяет, является ли токен двухфакторным, и возвращает userId.
     * Если неверный формат или просрочен, выбрасывает исключение.
     */
    public UUID validateTwoFactorToken(String jwt) {
        Claims claims = parseClaims(jwt);
        Boolean twofactor = claims.get("twofactor", Boolean.class);
        if (twofactor == null || !twofactor) {
            throw new IllegalArgumentException("Not a two-factor token");
        }
        String uid = claims.get("uid", String.class);
        return UUID.fromString(uid);
    }

    public long getTtlSeconds() {
        return props.getTtlSeconds();
    }
}