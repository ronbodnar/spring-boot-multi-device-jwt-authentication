package com.ronbodnar.auth.security.jwt;

import com.ronbodnar.auth.auth.domain.AuthenticationTokenType;
import com.ronbodnar.auth.auth.domain.TokenPair;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class JwtCookieServiceTest {

    private final JwtProperties properties = new JwtProperties(
            "unused-for-cookie-header-tests",
            new JwtProperties.Token("app_access", Duration.ofMinutes(5)),
            new JwtProperties.Token("app_refresh", Duration.ofDays(7))
    );

    @Test
    void createsHttpOnlyStrictCookiesWithConfiguredLifetimes() {
        JwtCookieService service = service("prod");

        List<String> cookies = service.createCookieHeaders(new TokenPair("access-jwt", "refresh-jwt"))
                .get(HttpHeaders.SET_COOKIE);

        assertThat(cookies).hasSize(2);
        assertThat(cookies).anySatisfy(cookie -> {
            assertThat(cookie).startsWith("app_access=access-jwt");
            assertThat(cookie).contains("Max-Age=300", "HttpOnly", "Secure", "SameSite=Strict", "Path=/");
        });
        assertThat(cookies).anySatisfy(cookie -> {
            assertThat(cookie).startsWith("app_refresh=refresh-jwt");
            assertThat(cookie).contains("Max-Age=604800", "HttpOnly", "Secure", "SameSite=Strict", "Path=/");
        });
    }

    @Test
    void doesNotMarkDevelopmentCookiesSecure() {
        JwtCookieService service = service("default");

        List<String> cookies = service.createCookieHeaders(new TokenPair("access-jwt", "refresh-jwt"))
                .get(HttpHeaders.SET_COOKIE);

        assertThat(cookies).allSatisfy(cookie -> assertThat(cookie).doesNotContain("Secure"));
    }

    @Test
    void readsConfiguredCookieAndReturnsNullWhenMissing() {
        JwtCookieService service = service("default");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("app_access", "access-jwt"));

        assertThat(service.getTokenFromRequest(request, AuthenticationTokenType.ACCESS)).isEqualTo("access-jwt");
        assertThat(service.getTokenFromRequest(request, AuthenticationTokenType.REFRESH)).isNull();
    }

    @Test
    void createsExpiredCookieWhenAskedToClearToken() {
        ResponseCookie cookie = service("prod").createJwtCookie(AuthenticationTokenType.ACCESS, "session", null);

        assertThat(cookie.getValue()).isEmpty();
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ZERO);
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
    }

    @Test
    void clearsBothCookiesBySettingZeroMaxAge() {
        List<String> cookies = service("default").clearCookieHeaders().get(HttpHeaders.SET_COOKIE);

        assertThat(cookies).hasSize(2);
        assertThat(cookies).anySatisfy(cookie -> {
            assertThat(cookie).startsWith("app_access=");
            assertThat(cookie).contains("Max-Age=0");
        });
        assertThat(cookies).anySatisfy(cookie -> {
            assertThat(cookie).startsWith("app_refresh=");
            assertThat(cookie).contains("Max-Age=0");
        });
    }

    private JwtCookieService service(String activeProfile) {
        return new JwtCookieService(activeProfile, mock(JwtService.class), properties);
    }
}
