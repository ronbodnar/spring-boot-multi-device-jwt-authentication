package com.ronbodnar.auth.auth.refreshtoken;

import com.ronbodnar.auth.exception.BusinessException;
import com.ronbodnar.auth.exception.ErrorCode;
import com.ronbodnar.auth.identity.user.UserAccount;
import com.ronbodnar.auth.identity.user.UserAccountService;
import com.ronbodnar.auth.security.jwt.JwtService;

import io.jsonwebtoken.Claims;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserAccountService userAccountService;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    @Test
    void storesOnlyTokenHashAndInvalidatesPreviousTokenForSameSession() throws Exception {
        String rawToken = "refresh-token-value";
        String sessionId = "client-session-123";
        Instant issuedAt = Instant.parse("2025-01-01T00:00:00Z");
        Instant expiresAt = Instant.parse("2025-01-08T00:00:00Z");
        Claims claims = mock(Claims.class);
        when(jwtService.getClaims(rawToken)).thenReturn(claims);
        when(claims.get("id", Long.class)).thenReturn(42L);
        when(claims.getIssuedAt()).thenReturn(Date.from(issuedAt));
        when(claims.getExpiration()).thenReturn(Date.from(expiresAt));
        when(claims.get("sessionId", String.class)).thenReturn(sessionId);

        refreshTokenService.createFromToken(rawToken, "192.0.2.1");

        verify(refreshTokenRepository).invalidateTokensForSessionId(sessionId);
        ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(tokenCaptor.capture());
        RefreshToken savedToken = tokenCaptor.getValue();
        assertThat(savedToken.getUserId()).isEqualTo(42L);
        assertThat(savedToken.getSessionId()).isEqualTo(sessionId);
        assertThat(savedToken.getTokenHash()).hasSize(32).containsExactly(sha256(rawToken));
        assertThat(savedToken.getIpAddress()).isEqualTo("192.0.2.1");
        assertThat(savedToken.getIssuedAt()).isEqualTo(issuedAt);
        assertThat(savedToken.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(savedToken.isValid()).isTrue();
    }

    @Test
    void validatesTokenAndReturnsItsUser() throws Exception {
        String rawToken = "valid-refresh-token";
        RefreshToken savedToken = new RefreshToken(
                42L,
                "client-session-123",
                sha256(rawToken),
                "192.0.2.1",
                Instant.now(),
                Instant.now().plusSeconds(60)
        );
        UserAccount user = new UserAccount();
        when(refreshTokenRepository.findByTokenHash(any(byte[].class))).thenReturn(Optional.of(savedToken));
        when(userAccountService.getById(42L)).thenReturn(user);

        assertThat(refreshTokenService.validateAndGetUser(rawToken)).isSameAs(user);

        ArgumentCaptor<byte[]> hashCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(refreshTokenRepository).findByTokenHash(hashCaptor.capture());
        assertThat(hashCaptor.getValue()).containsExactly(sha256(rawToken));
    }

    @Test
    void rejectsExpiredOrRevokedTokens() throws Exception {
        String rawToken = "inactive-refresh-token";
        RefreshToken expiredToken = new RefreshToken(
                42L,
                "client-session-123",
                sha256(rawToken),
                "192.0.2.1",
                Instant.now().minusSeconds(120),
                Instant.now().minusSeconds(60)
        );
        when(refreshTokenRepository.findByTokenHash(any(byte[].class))).thenReturn(Optional.of(expiredToken));

        assertThatThrownBy(() -> refreshTokenService.validateAndGetUser(rawToken))
                .isInstanceOf(BusinessException.class)
                .extracting(exception -> ((BusinessException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);

        expiredToken.setExpiresAt(Instant.now().plusSeconds(60));
        expiredToken.setValid(false);
        assertThatThrownBy(() -> refreshTokenService.validateAndGetUser(rawToken))
                .isInstanceOf(BusinessException.class)
                .extracting(exception -> ((BusinessException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
        verifyNoInteractions(userAccountService);
    }

    @Test
    void rejectsRefreshTokenMissingFromPersistence() throws Exception {
        when(refreshTokenRepository.findByTokenHash(any(byte[].class))).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.validateAndGetUser("unknown-token"))
                .isInstanceOf(BusinessException.class)
                .extracting(exception -> ((BusinessException) exception).getErrorCode())
                .isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);

        verifyNoInteractions(userAccountService);
    }

    private static byte[] sha256(String token) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
    }
}
