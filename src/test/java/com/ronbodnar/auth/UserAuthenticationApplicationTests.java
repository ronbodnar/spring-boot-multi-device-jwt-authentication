package com.ronbodnar.auth;

import com.ronbodnar.auth.identity.role.RoleRepository;

import org.junit.jupiter.api.Test;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestConstructor;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestConstructor(autowireMode = TestConstructor.AutowireMode.ALL)
class UserAuthenticationApplicationTests {

	private final RoleRepository roleRepository;

	UserAuthenticationApplicationTests(RoleRepository roleRepository) {
		this.roleRepository = roleRepository;
	}

	@Test
	void contextLoads() {
	}

	@Test
	void initializesDefaultUserRoleForRegistration() {
		assertThat(roleRepository.findByName("USER")).isPresent();
	}

}
