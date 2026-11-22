package com.ronbodnar.auth.auth.listener;

import com.ronbodnar.auth.auth.event.UserRegisteredEvent;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Slf4j
@Component
public class WelcomeEmailListener {

    private final String appName;

    public WelcomeEmailListener(@Value("${app.name}") String appName) {
        this.appName = appName;
    }

    @Async("emailTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void sendWelcomeEmail(UserRegisteredEvent event) {
        log.info("Received event to send welcome email: " + event);
    }

}