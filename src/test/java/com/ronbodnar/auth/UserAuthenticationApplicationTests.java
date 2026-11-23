package com.ronbodnar.auth;

import com.ronbodnar.auth.auth.refreshtoken.RefreshToken;
import com.ronbodnar.auth.auth.refreshtoken.RefreshTokenRepository;
import com.ronbodnar.auth.auth.refreshtoken.RefreshTokenService;
import com.ronbodnar.auth.identity.role.RoleRepository;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class UserAuthenticationApplicationTests {

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private RefreshTokenService refreshTokenService;

	@Test
	void contextLoads() {
	}

	@Test
	void initializesDefaultUserRoleForRegistration() {
		assertThat(roleRepository.findByName("USER")).isPresent();
	}

	@Test
	void logoutInvalidatesTheRefreshToken() throws Exception {
		String rawToken = "refresh-token-to-revoke";
		byte[] tokenHash = MessageDigest.getInstance("SHA-256")
				.digest(rawToken.getBytes(StandardCharsets.UTF_8));
		RefreshToken savedToken = refreshTokenRepository.saveAndFlush(new RefreshToken(
				1L,
				"session-12345678",
				tokenHash,
				"127.0.0.1",
				Instant.now(),
				Instant.now().plusSeconds(60)
		));

		refreshTokenService.invalidateToken(rawToken);

		assertThat(refreshTokenRepository.findById(savedToken.getId()))
				.get()
				.extracting(RefreshToken::isValid)
				.isEqualTo(false);
	}

}
