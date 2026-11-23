package com.ronbodnar.auth.security.jwt;

import com.ronbodnar.auth.auth.domain.AuthenticationTokenType;
import com.ronbodnar.auth.security.adapter.SecurityUserDetails;
import com.ronbodnar.auth.exception.BusinessException;
import com.ronbodnar.auth.exception.ErrorCode;

import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
public class JwtService {

    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public Claims getClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getKeyWithSecret())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException ignored) {
            return null;
        }
    }

    public boolean isInvalid(String token) {
        if (token == null) {
            return true;
        }
        try {
            Jwts.parser()
                    .verifyWith(getKeyWithSecret())
                    .build()
                    .parseSignedClaims(token);

            return false;
        } catch (JwtException | IllegalArgumentException e) {
            String errorName = e.getClass().getSimpleName();
            if (!errorName.equals("ExpiredJwtException")) {
                log.warn("Invalid JWT: {} (truncated token: {})", e.getClass().getSimpleName(), token.isEmpty() ? "" : token.substring(0, 6));
            }
        }
        return true;
    }

    public String generateAuthToken(
            AuthenticationTokenType tokenType,
            String sessionId,
            SecurityUserDetails userPrincipal
    ) {
        if (userPrincipal == null) {
            throw new BusinessException(ErrorCode.INVALID_ACCESS_TOKEN, "User Principal not found for %s token request".formatted(tokenType.name()));
        }

        Map<String, Object> claims = new HashMap<>(Map.of(
                "id", userPrincipal.getId(),
                "sessionId", sessionId
        ));

        if (tokenType == AuthenticationTokenType.ACCESS) {
            claims.put("username", userPrincipal.getUsername());
            claims.put("roles", userPrincipal.getAuthorities());
        }

        String subject = userPrincipal.getUsername();
        long expiration = jwtProperties.token(tokenType).expiration().toMillis();

        return generateToken(subject, expiration, claims);
    }

    private String generateToken(
            String subject,
            long expiration,
            Map<String, ?> claims
    ) {
        log.debug("Generating JWT expiring in {}ms for {} with claims {}", expiration, subject, claims);

        Key signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.secret()));

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .id(UUID.randomUUID().toString())
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + expiration))
                .signWith(signingKey)
                .compact();
    }

    private SecretKey getKeyWithSecret() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.secret()));
    }

}