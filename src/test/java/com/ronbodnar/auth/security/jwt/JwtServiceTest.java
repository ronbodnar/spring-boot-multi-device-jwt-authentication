package com.ronbodnar.auth.security.jwt;

import com.ronbodnar.auth.auth.domain.AuthenticationTokenType;
import com.ronbodnar.auth.security.adapter.SecurityUserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private static final String SECRET = Base64.getEncoder().encodeToString(new byte[32]);
    private static final String SESSION_ID = "client-session-123";

    private JwtService jwtService;
    private SecurityUserDetails userDetails;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties(
                SECRET,
                new JwtProperties.Token("access", Duration.ofMinutes(5)),
                new JwtProperties.Token("refresh", Duration.ofDays(7))
        );
        jwtService = new JwtService(properties);
        userDetails = new SecurityUserDetails(
                42L,
                "alice",
                "encoded-password",
                List.of(new SimpleGrantedAuthority("USER"))
        );
    }

    @Test
    void accessTokenContainsIdentitySessionAndAuthorities() {
        String token = jwtService.generateAuthToken(AuthenticationTokenType.ACCESS, SESSION_ID, userDetails);

        assertThat(jwtService.isInvalid(token)).isFalse();
        Claims claims = jwtService.getClaims(token);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.get("id", Long.class)).isEqualTo(42L);
        assertThat(claims.get("sessionId", String.class)).isEqualTo(SESSION_ID);
        assertThat(claims.get("roles")).isNotNull();
        assertThat(claims.getId()).isNotBlank();
        assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());
        assertThat(jwtService.generateAuthToken(AuthenticationTokenType.ACCESS, SESSION_ID, userDetails))
                .isNotEqualTo(token);
    }

    @Test
    void refreshTokenDoesNotContainAccessTokenAuthorities() {
        String token = jwtService.generateAuthToken(AuthenticationTokenType.REFRESH, SESSION_ID, userDetails);

        Claims claims = jwtService.getClaims(token);

        assertThat(jwtService.isInvalid(token)).isFalse();
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.get("sessionId", String.class)).isEqualTo(SESSION_ID);
        assertThat(claims.containsKey("roles")).isFalse();
    }

    @Test
    void rejectsMalformedAndIncorrectlySignedTokens() {
        String token = jwtService.generateAuthToken(AuthenticationTokenType.ACCESS, SESSION_ID, userDetails);
        byte[] otherKey = new byte[32];
        Arrays.fill(otherKey, (byte) 1);
        JwtService otherKeyService = new JwtService(new JwtProperties(
                Base64.getEncoder().encodeToString(otherKey),
                new JwtProperties.Token("access", Duration.ofMinutes(5)),
                new JwtProperties.Token("refresh", Duration.ofDays(7))
        ));

        assertThat(jwtService.getClaims("not-a-jwt")).isNull();
        assertThat(jwtService.isInvalid("not-a-jwt")).isTrue();
        assertThat(otherKeyService.getClaims(token)).isNull();
        assertThat(otherKeyService.isInvalid(token)).isTrue();
        assertThat(jwtService.isInvalid(null)).isTrue();
    }

    @Test
    void rejectsExpiredTokens() {
        long now = System.currentTimeMillis();
        String expiredToken = Jwts.builder()
                .subject("alice")
                .issuedAt(new Date(now - 2_000))
                .expiration(new Date(now - 1_000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET)))
                .compact();

        assertThat(jwtService.getClaims(expiredToken)).isNull();
        assertThat(jwtService.isInvalid(expiredToken)).isTrue();
    }
}
