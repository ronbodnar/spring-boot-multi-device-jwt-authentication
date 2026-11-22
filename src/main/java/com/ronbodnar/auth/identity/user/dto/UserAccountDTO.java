package com.ronbodnar.auth.identity.user.dto;

import com.ronbodnar.auth.identity.role.Role;
import com.ronbodnar.auth.identity.user.UserAccount;

import java.util.Set;
import java.util.stream.Collectors;

public record UserAccountDTO(
        Long id,
        String username,
        String email,
        String givenName,
        String familyName,
        Set<String> roles
) {

    public static UserAccountDTO from(UserAccount userAccount) {
        return new UserAccountDTO(
                userAccount.getId(),
                userAccount.getUsername(),
                userAccount.getEmail(),
                userAccount.getGivenName(),
                userAccount.getFamilyName(),
                userAccount.getRoles().stream()
                        .map(Role::getName)
                        .collect(Collectors.toSet())
        );
    }
}