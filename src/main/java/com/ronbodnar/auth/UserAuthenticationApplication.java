package com.ronbodnar.auth;

import com.ronbodnar.auth.identity.user.UserAccount;
import com.ronbodnar.auth.identity.user.UserAccountRepository;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@ConfigurationPropertiesScan
@SpringBootApplication
public class UserAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserAuthenticationApplication.class, args);
	}

	@Bean
	CommandLineRunner init(UserAccountRepository userRepository, PasswordEncoder passwordEncoder) {
		return args -> {
			UserAccount user = new UserAccount();
			user.setUsername("test");
			user.setPassword(passwordEncoder.encode("test"));
			user.setEmail("test@test.com");
			user.setFamilyName("Test FN");
			user.setGivenName("Test GN");
			userRepository.save(user);
			System.out.println("Added user: " + user.getEmail());
		};
	}
}
