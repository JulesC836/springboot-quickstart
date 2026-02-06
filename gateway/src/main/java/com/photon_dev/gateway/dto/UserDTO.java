package com.photon_dev.gateway.dto;

public record UserDTO(
        String name,
        String username,
        String role,
        String access_token,
        String refresh_token
) {
}
