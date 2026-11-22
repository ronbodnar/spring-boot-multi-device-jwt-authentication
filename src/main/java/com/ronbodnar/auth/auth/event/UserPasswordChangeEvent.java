package com.ronbodnar.auth.auth.event;

public record UserPasswordChangeEvent(String email, String username) {}