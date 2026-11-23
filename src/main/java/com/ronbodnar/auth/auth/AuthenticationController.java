package com.ronbodnar.auth.auth;

import com.ronbodnar.auth.auth.domain.AuthenticationResponse;
import com.ronbodnar.auth.auth.domain.AuthenticationTokenType;
import com.ronbodnar.auth.auth.dto.ForgotPasswordRequest;
import com.ronbodnar.auth.auth.dto.LoginRequest;
import com.ronbodnar.auth.auth.dto.RegisterRequest;
import com.ronbodnar.auth.auth.dto.ResetPasswordRequest;
import com.ronbodnar.auth.exception.BusinessException;
import com.ronbodnar.auth.exception.ErrorCode;
import com.ronbodnar.auth.identity.user.dto.UserAccountChangeRequest;
import com.ronbodnar.auth.identity.user.dto.UserAccountDTO;
import com.ronbodnar.auth.security.adapter.SecurityUserDetails;
import com.ronbodnar.auth.security.jwt.JwtCookieService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import lombok.Getter;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Getter
@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final JwtCookieService jwtCookieService;
    private final AuthenticationService authenticationService;

    public AuthenticationController(
            JwtCookieService jwtCookieService,
            AuthenticationService authenticationService
    ) {
        this.jwtCookieService = jwtCookieService;
        this.authenticationService = authenticationService;
    }

    @GetMapping("/me")
    public UserAccountDTO getCurrentUser(@AuthenticationPrincipal SecurityUserDetails userDetails) {
        if (userDetails == null) {
            throw new BusinessException(ErrorCode.INVALID_ACCESS_TOKEN);
        }

        return UserAccountDTO.from(authenticationService.getCurrentUser(userDetails));
    }

    @PutMapping("/me")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void updateCurrentUser(
            @RequestBody @Valid UserAccountChangeRequest request,
            @AuthenticationPrincipal SecurityUserDetails securityUser
    ) {
        if (securityUser == null) {
            throw new BusinessException(ErrorCode.INVALID_ACCESS_TOKEN);
        }

        authenticationService.updateCurrentUser(request, securityUser);
    }

    @PostMapping("/login")
    public ResponseEntity<UserAccountDTO> login(
            @RequestBody @Valid LoginRequest loginDTO,
            HttpServletRequest request
    ) {
        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        AuthenticationResponse response = authenticationService.authenticate(loginDTO, ip, userAgent);

        HttpHeaders headers = jwtCookieService.createCookieHeaders(response.tokenPair());

        return ResponseEntity.ok().headers(headers).body(UserAccountDTO.from(response.userAccount()));
    }

    @PostMapping("/register")
    public ResponseEntity<UserAccountDTO> register(
            @RequestBody @Valid RegisterRequest registerRequest,
            HttpServletRequest request
    ) {
        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        AuthenticationResponse response = authenticationService.register(registerRequest, ip, userAgent);

        HttpHeaders headers = jwtCookieService.createCookieHeaders(response.tokenPair());

        return ResponseEntity.status(HttpStatus.CREATED)
                .headers(headers)
                .body(UserAccountDTO.from(response.userAccount()));
    }

    @PostMapping("/request-password-reset")
    public void requestPasswordReset(@RequestBody ForgotPasswordRequest request) {
        authenticationService.requestPasswordReset(request.usernameOrEmail());
    }

    @PostMapping("/reset-password")
    public void resetPassword(@RequestBody ResetPasswordRequest request) {
        authenticationService.resetPassword(request.token(), request.newPassword());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        String refreshToken = jwtCookieService.getTokenFromRequest(request, AuthenticationTokenType.REFRESH);
        authenticationService.logout(refreshToken);

        HttpHeaders headers = jwtCookieService.clearCookieHeaders();

        return ResponseEntity.ok().headers(headers).build();
    }

    @GetMapping("/refresh")
    public ResponseEntity<UserAccountDTO> refresh(HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        String refreshToken = jwtCookieService.getTokenFromRequest(request, AuthenticationTokenType.REFRESH);

        AuthenticationResponse response = authenticationService.refreshAccessToken(refreshToken, ip, userAgent);

        HttpHeaders headers = jwtCookieService.createCookieHeaders(response.tokenPair());

        return ResponseEntity.ok().headers(headers).body(UserAccountDTO.from(response.userAccount()));
    }
}