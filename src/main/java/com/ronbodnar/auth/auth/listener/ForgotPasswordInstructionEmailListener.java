package com.ronbodnar.auth.auth.listener;

import com.ronbodnar.auth.auth.event.UserForgotPasswordRequestEvent;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class ForgotPasswordInstructionEmailListener {

    private final String appName;
    private final String passwordResetUrl;

    public ForgotPasswordInstructionEmailListener(
            @Value("${app.name}") String appName,
            @Value("${app.security.password-reset-url}") String passwordResetUrl
    ) {
        this.appName = appName;
        this.passwordResetUrl = passwordResetUrl;
    }

    @Async("emailTaskExecutor")
    @EventListener
    public void sendPasswordResetEmail(UserForgotPasswordRequestEvent event) {
        // Send email
        log.info("Received event to send password reset email: " + event);
        log.info("Password reset url: " + passwordResetUrl);
    }
}