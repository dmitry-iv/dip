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

    public static final String CLAIM_TYPE = "typ";
    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_MFA_PENDING = "mfa_pending";

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

    public String issueToken(UUID userId, String username, List<String> roles) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(props.getTtlSeconds());
        UUID jti = UUID.randomUUID();

        return Jwts.builder()
                .subject(username)
                .id(jti.toString())
                .issuer(props.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .claim("uid", userId.toString())
                .claim("roles", roles)
                .claim(CLAIM_TYPE, TYPE_ACCESS)
                .signWith(key)
                .compact();
    }

    public String issueMfaPendingToken(UUID userId, String username, long ttlSeconds) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(ttlSeconds);
        return Jwts.builder()
                .subject(username)
                .id(UUID.randomUUID().toString())
                .issuer(props.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .claim("uid", userId.toString())
                .claim(CLAIM_TYPE, TYPE_MFA_PENDING)
                .signWith(key)
                .compact();
    }

    public Claims parseClaims(String jwt) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    public UUID parseMfaPendingTokenUserId(String token) {
        Claims c = parseClaims(token);
        if (!TYPE_MFA_PENDING.equals(c.get(CLAIM_TYPE, String.class))) {
            throw new IllegalArgumentException("Not an MFA-pending token");
        }
        return UUID.fromString(c.get("uid", String.class));
    }

    public long getTtlSeconds() {
        return props.getTtlSeconds();
    }
}