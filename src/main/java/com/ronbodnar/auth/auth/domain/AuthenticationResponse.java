package com.ronbodnar.auth.auth.domain;

import com.ronbodnar.auth.identity.user.UserAccount;

public record AuthenticationResponse(UserAccount userAccount, TokenPair tokenPair) {}
