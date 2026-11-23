package com.ronbodnar.auth.auth;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.Test;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.context.TestConstructor;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestConstructor(autowireMode = TestConstructor.AutowireMode.ALL)
class AuthenticationApiIntegrationTest {

    private static final String AUTH_PATH = "/api/v1/auth";
    private static final String ACCESS_COOKIE = "app_access";
    private static final String REFRESH_COOKIE = "app_refresh";
    private static final String PASSWORD = "correct-horse-battery";

    private final MockMvc mockMvc;

    AuthenticationApiIntegrationTest(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Test
    void registrationSetsAuthCookiesAndAccessCookieAuthenticatesCurrentUser() throws Exception {
        String username = uniqueUsername();
        MvcResult result = register(username, uniqueEmail(), UUID.randomUUID().toString());

        assertThat(result.getResponse().getStatus()).isEqualTo(201);
        assertThat(result.getResponse().getHeaders(HttpHeaders.SET_COOKIE)).hasSize(2);
        assertThat(result.getResponse().getHeaders(HttpHeaders.SET_COOKIE))
                .allSatisfy(cookie -> assertThat(cookie).contains("HttpOnly", "SameSite=Strict"));

        String accessToken = cookieValue(result, ACCESS_COOKIE);
        mockMvc.perform(get(AUTH_PATH + "/me").cookie(new Cookie(ACCESS_COOKIE, accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username));
    }

    @Test
    void rejectsRegistrationWithInvalidFields() throws Exception {
        mockMvc.perform(post(AUTH_PATH + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "x",
                                  "password": "short",
                                  "confirmPassword": "short",
                                  "email": "not-an-email",
                                  "sessionId": ""
                                }
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void requiresAccessCookieForCurrentUserEndpoint() throws Exception {
        mockMvc.perform(get(AUTH_PATH + "/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsInvalidCredentialsWithoutIssuingCookies() throws Exception {
        String username = uniqueUsername();
        register(username, uniqueEmail(), UUID.randomUUID().toString());

        MvcResult failedLogin = mockMvc.perform(post(AUTH_PATH + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "incorrect-password",
                                  "sessionId": "%s"
                                }
                                """.formatted(username, UUID.randomUUID())))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(failedLogin.getResponse().getHeaders(HttpHeaders.SET_COOKIE)).isEmpty();
    }

    @Test
    void rejectsDuplicateUsernameWithoutIssuingCookies() throws Exception {
        String username = uniqueUsername();
        register(username, uniqueEmail(), UUID.randomUUID().toString());

        MvcResult duplicate = mockMvc.perform(post(AUTH_PATH + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(username, uniqueEmail(), UUID.randomUUID().toString())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors[0].errorCode").value("USERNAME_ALREADY_IN_USE"))
                .andReturn();

        assertThat(duplicate.getResponse().getHeaders(HttpHeaders.SET_COOKIE)).isEmpty();
    }

    @Test
    void refreshRotationAndLogoutAreScopedToOneClientSession() throws Exception {
        String username = uniqueUsername();
        String email = uniqueEmail();
        String firstSessionId = UUID.randomUUID().toString();
        String secondSessionId = UUID.randomUUID().toString();
        MvcResult firstRegistration = register(username, email, firstSessionId);
        MvcResult secondLogin = login(username, secondSessionId);

        String firstRefreshToken = cookieValue(firstRegistration, REFRESH_COOKIE);
        String secondRefreshToken = cookieValue(secondLogin, REFRESH_COOKIE);

        MvcResult secondRefresh = refresh(secondRefreshToken, 200);
        String rotatedSecondRefreshToken = cookieValue(secondRefresh, REFRESH_COOKIE);
        refresh(secondRefreshToken, 401);

        MvcResult firstRefresh = refresh(firstRefreshToken, 200);
        String rotatedFirstRefreshToken = cookieValue(firstRefresh, REFRESH_COOKIE);
        MvcResult logout = mockMvc.perform(post(AUTH_PATH + "/logout")
                        .cookie(new Cookie(REFRESH_COOKIE, rotatedFirstRefreshToken)))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(logout.getResponse().getHeaders(HttpHeaders.SET_COOKIE))
                .allSatisfy(cookie -> assertThat(cookie).contains("Max-Age=0"));

        refresh(rotatedFirstRefreshToken, 401);
        refresh(rotatedSecondRefreshToken, 200);
    }

    @Test
    void corsPreflightUsesConfiguredOriginAndAllowsCredentials() throws Exception {
        mockMvc.perform(options(AUTH_PATH + "/login")
                        .header(HttpHeaders.ORIGIN, "http://localhost:4200")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                        .string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:4200"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                        .string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
    }

    private MvcResult register(String username, String email, String sessionId) throws Exception {
        return mockMvc.perform(post(AUTH_PATH + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(username, email, sessionId)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value(username))
                .andReturn();
    }

    private MvcResult login(String username, String sessionId) throws Exception {
        return mockMvc.perform(post(AUTH_PATH + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "%s",
                                  "sessionId": "%s"
                                }
                                """.formatted(username, PASSWORD, sessionId)))
                .andExpect(status().isOk())
                .andReturn();
    }

    private MvcResult refresh(String refreshToken, int expectedStatus) throws Exception {
        return mockMvc.perform(get(AUTH_PATH + "/refresh")
                        .cookie(new Cookie(REFRESH_COOKIE, refreshToken)))
                .andExpect(status().is(expectedStatus))
                .andReturn();
    }

    private static String registrationJson(String username, String email, String sessionId) {
        return """
                {
                  "username": "%s",
                  "password": "%s",
                  "confirmPassword": "%s",
                  "email": "%s",
                  "sessionId": "%s"
                }
                """.formatted(username, PASSWORD, PASSWORD, email, sessionId);
    }

    private static String cookieValue(MvcResult result, String cookieName) {
        return result.getResponse().getHeaders(HttpHeaders.SET_COOKIE).stream()
                .filter(cookie -> cookie.startsWith(cookieName + "="))
                .map(cookie -> cookie.substring(cookieName.length() + 1).split(";", 2)[0])
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing Set-Cookie header for " + cookieName));
    }

    private static String uniqueUsername() {
        return "user_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    private static String uniqueEmail() {
        return "test-" + UUID.randomUUID() + "@example.com";
    }
}
