package com.ronbodnar.auth.security.jwt;

import com.ronbodnar.auth.auth.domain.AuthenticationTokenType;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "app.security.jwt")
public record JwtProperties(String secret, Token accessToken, Token refreshToken) {

    public Token token(AuthenticationTokenType tokenType) {
        return switch (tokenType) {
            case ACCESS -> accessToken;
            case REFRESH -> refreshToken;
        };
    }

    public record Token(String name, Duration expiration) {}

}