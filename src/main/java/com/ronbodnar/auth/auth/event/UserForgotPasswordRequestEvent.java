package com.ronbodnar.auth.auth.event;

public record UserForgotPasswordRequestEvent(String email, String username, String token) {}