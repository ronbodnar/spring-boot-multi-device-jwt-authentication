package com.ronbodnar.auth.identity.user.dto;

import com.ronbodnar.auth.identity.user.UserAccount;

public record UserAccountSummaryDTO(
        Long id,
        String username,
        String fullName
) {

    public static UserAccountSummaryDTO from(UserAccount userAccount) {
        return new UserAccountSummaryDTO(
                userAccount.getId(),
                userAccount.getUsername(),
                userAccount.getFullName()
        );
    }
}