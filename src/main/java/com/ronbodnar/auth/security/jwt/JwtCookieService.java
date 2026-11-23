package com.ronbodnar.auth.security.jwt;

import com.ronbodnar.auth.auth.domain.AuthenticationTokenType;
import com.ronbodnar.auth.auth.domain.TokenPair;
import com.ronbodnar.auth.security.adapter.SecurityUserDetails;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.web.util.WebUtils;

@Service
public class JwtCookieService {

    private final String activeProfile;

    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    public JwtCookieService(
            @Value("${spring.profiles.active:default}") String activeProfile,
            JwtService jwtService,
            JwtProperties jwtProperties
    ) {
        this.activeProfile = activeProfile;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
    }

    public String getTokenFromRequest(HttpServletRequest request, AuthenticationTokenType tokenType) {
        Cookie cookie = WebUtils.getCookie(request, jwtProperties.token(tokenType).name());
        if (cookie == null) {
            return null;
        }
        return cookie.getValue();
    }

    public HttpHeaders createCookieHeaders(TokenPair tokenPair) {
        ResponseCookie accessCookie = buildCookie(
                AuthenticationTokenType.ACCESS,
                tokenPair.accessToken(),
                jwtProperties.accessToken().expiration().toMillis()
        );

        ResponseCookie refreshCookie = buildCookie(
                AuthenticationTokenType.REFRESH,
                tokenPair.refreshToken(),
                jwtProperties.refreshToken().expiration().toMillis()
        );

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, accessCookie.toString());
        headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        return headers;
    }

    public HttpHeaders clearCookieHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(
                HttpHeaders.SET_COOKIE,
                buildCookie(AuthenticationTokenType.ACCESS, "", 0).toString()
        );
        headers.add(
                HttpHeaders.SET_COOKIE,
                buildCookie(AuthenticationTokenType.REFRESH, "", 0).toString()
        );
        return headers;
    }

    public ResponseCookie createJwtCookie(
            AuthenticationTokenType tokenType,
            String sessionId,
            SecurityUserDetails userPrincipal
    ) {
        if (userPrincipal == null) {
            return buildCookie(tokenType, "", 0);
        }

        long expiration = jwtProperties.token(tokenType).expiration().toMillis();

        String jwt = jwtService.generateAuthToken(tokenType, sessionId, userPrincipal);

        return buildCookie(tokenType, jwt, expiration);
    }

    private ResponseCookie buildCookie(AuthenticationTokenType tokenType, String jwt, long maxAgeSeconds) {
        String cookieName = jwtProperties.token(tokenType).name();
        boolean isProdEnvironment = activeProfile.startsWith("prod");

        return ResponseCookie
                .from(cookieName, jwt)
                .path("/")
                .maxAge(maxAgeSeconds)
                .secure(isProdEnvironment)
                .httpOnly(true)
                .sameSite("Strict")
                .build();
    }
}
