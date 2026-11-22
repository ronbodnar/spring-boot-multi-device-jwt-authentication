package com.ronbodnar.auth.auth.listener;

import com.ronbodnar.auth.auth.event.UserPasswordChangeEvent;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Slf4j
@Component
public class PasswordChangeEmailListener {

    private final String appName;

    public PasswordChangeEmailListener(@Value("${app.name}") String appName) {
        this.appName = appName;
    }

    @Async("emailTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void sendPasswordChangeEmail(UserPasswordChangeEvent event) {
        log.info("Received event to send password change email: " + event);
    }

}