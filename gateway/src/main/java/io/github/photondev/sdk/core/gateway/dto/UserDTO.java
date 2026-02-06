package io.github.photondev.sdk.core.gateway.dto;

import java.util.UUID;

public record UserDTO(
        UUID id,
        String name,
        String username,
        String role,
        String access_token,
        String refresh_token
) {
}
