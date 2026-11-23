package com.ronbodnar.auth.auth;

import com.ronbodnar.auth.auth.domain.AuthenticationResponse;
import com.ronbodnar.auth.auth.domain.AuthenticationTokenType;
import com.ronbodnar.auth.auth.domain.TokenPair;
import com.ronbodnar.auth.auth.dto.LoginRequest;
import com.ronbodnar.auth.auth.dto.RegisterRequest;
import com.ronbodnar.auth.auth.event.UserForgotPasswordRequestEvent;
import com.ronbodnar.auth.auth.event.UserPasswordChangeEvent;
import com.ronbodnar.auth.auth.event.UserRegisteredEvent;
import com.ronbodnar.auth.auth.refreshtoken.RefreshTokenService;
import com.ronbodnar.auth.exception.BusinessException;
import com.ronbodnar.auth.exception.ErrorCode;
import com.ronbodnar.auth.identity.user.UserAccount;
import com.ronbodnar.auth.identity.user.UserAccountService;
import com.ronbodnar.auth.identity.user.dto.UserAccountChangeRequest;
import com.ronbodnar.auth.security.adapter.SecurityUserDetails;
import com.ronbodnar.auth.security.jwt.JwtService;

import io.jsonwebtoken.Claims;

import lombok.extern.slf4j.Slf4j;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
public class AuthenticationService {

    private final JwtService jwtService;

    private final UserAccountService userAccountService;

    private final RefreshTokenService refreshTokenService;

    private final ApplicationEventPublisher eventPublisher;

    private final PasswordResetService passwordResetService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(
            JwtService jwtService,
            UserAccountService userAccountService,
            RefreshTokenService refreshTokenService,
            ApplicationEventPublisher eventPublisher,
            PasswordResetService passwordResetService,
            AuthenticationManager authenticationManager
    ) {
        this.jwtService = jwtService;
        this.userAccountService = userAccountService;
        this.refreshTokenService = refreshTokenService;
        this.eventPublisher = eventPublisher;
        this.passwordResetService = passwordResetService;
        this.authenticationManager = authenticationManager;
    }

    public UserAccount getCurrentUser(@AuthenticationPrincipal SecurityUserDetails userDetails) {
        return userAccountService.getById(userDetails.getId());
    }

    public AuthenticationResponse authenticate(
            LoginRequest loginRequest,
            String ip,
            String userAgent
    ) {
        log.info(
                "Login attempt: username={}, sessionId={}, ip={}, userAgent={}",
                loginRequest.username(),
                loginRequest.sessionId(),
                ip,
                userAgent
        );

        String username = loginRequest.username();

        Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(
                username,
                loginRequest.password()
        );

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(authenticationRequest);
        } catch (DisabledException e) {
            throw new BusinessException(
                    ErrorCode.AUTH_USER_BLOCKED,
                    "Login failed: username=%s, reason=%s"
                            .formatted(username, "User is disabled")
            );
        } catch (LockedException e) {
            throw new BusinessException(
                    ErrorCode.AUTH_USER_LOCKED,
                    "Login failed: username=%s, reason=%s"
                            .formatted(username, "User is locked")
            );
        } catch (BadCredentialsException e) {
            throw new BusinessException(
                    ErrorCode.INVALID_CREDENTIALS,
                    "Login failed: username=%s, reason=%s"
                            .formatted(username, "Invalid credentials")
            );
        }

        SecurityUserDetails securityUser = (SecurityUserDetails) authentication.getPrincipal();

        if (securityUser == null) {
            throw new BusinessException(
                    ErrorCode.INVALID_AUTHENTICATION,
                    "Authenticated principal is missing"
            );
        }

        TokenPair tokenPair = createTokenPair(securityUser, loginRequest.sessionId(), ip);

        log.info(
                "Login successful: id={}, username={}, ip={}",
                securityUser.getId(),
                username,
                ip
        );

        return new AuthenticationResponse(getCurrentUser(securityUser), tokenPair);
    }

    public void updateCurrentUser(UserAccountChangeRequest request, SecurityUserDetails securityUser) {
        userAccountService.updateUserAccount(request, securityUser);
    }

    public void logout(String refreshToken) {
        if (refreshToken != null) {
            refreshTokenService.invalidateToken(refreshToken);
        }
    }

    @Transactional
    public AuthenticationResponse register(RegisterRequest registerRequest, String ip, String userAgent) {
        log.info("Register request: {}", registerRequest);

        UserAccount created = userAccountService.create(registerRequest);

        SecurityUserDetails securityUser = SecurityUserDetails.build(created);

        TokenPair tokenPair = createTokenPair(securityUser, registerRequest.sessionId(), ip);

        eventPublisher.publishEvent(new UserRegisteredEvent(created.getUsername(), created.getEmail()));

        return new AuthenticationResponse(created, tokenPair);
    }

    public void requestPasswordReset(String usernameOrEmail) {
        log.info("Password reset request made for email: {}", usernameOrEmail);

        UserAccount userAccount = userAccountService.getByUsernameOrEmailSilent(usernameOrEmail);

        if (userAccount == null) {
            return;
        }

        String token = passwordResetService.createResetToken(userAccount.getEmail());

        eventPublisher.publishEvent(new UserForgotPasswordRequestEvent(userAccount.getEmail(), userAccount.getUsername(), token));
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        String email = passwordResetService.validateTokenAndGetEmail(token);
        if (email == null) {
            throw new BusinessException(ErrorCode.INVALID_PASSWORD_RESET_TOKEN, "The provided token is invalid or has expired.");
        }

        UserAccount user = userAccountService.resetUserPassword(email, newPassword);

        passwordResetService.invalidateToken(token);

        eventPublisher.publishEvent(new UserPasswordChangeEvent(email, user.getUsername()));
    }

    @Transactional
    public AuthenticationResponse refreshAccessToken(String refreshToken, String ip, String userAgent) {
        log.info("Refresh attempt: ip={}, userAgent={}", ip, userAgent);

        if (jwtService.isInvalid(refreshToken)) {
            throw new BusinessException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        Claims claims = jwtService.getClaims(refreshToken);

        String sessionId = claims.get("sessionId", String.class);
        if (sessionId == null) {
            throw new BusinessException(
                    ErrorCode.INVALID_REFRESH_TOKEN,
                    "Token has valid claims, but sessionId is not one of them."
            );
        }

        UserAccount userAccount = refreshTokenService.validateAndGetUser(refreshToken);

        SecurityUserDetails securityUser = SecurityUserDetails.build(userAccount);

        TokenPair tokenPair = createTokenPair(securityUser, sessionId, ip);

        log.info(
                "Refresh successful: id={}, username={}, ip={}, sessionId={}\n",
                securityUser.getId(),
                securityUser.getUsername(),
                ip,
                sessionId
        );

        return new AuthenticationResponse(userAccount, tokenPair);
    }

    private TokenPair createTokenPair(SecurityUserDetails securityUser, String sessionId, String ip) {
        String accessToken = jwtService.generateAuthToken(
                AuthenticationTokenType.ACCESS,
                sessionId,
                securityUser
        );

        String refreshToken = jwtService.generateAuthToken(
                AuthenticationTokenType.REFRESH,
                sessionId,
                securityUser
        );

        refreshTokenService.createFromToken(refreshToken, ip);

        return new TokenPair(accessToken, refreshToken);
    }

}