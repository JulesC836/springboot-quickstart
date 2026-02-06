package io.github.photondev.sdk.core.auth.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String name;
    private String username;
    private String password;
    private String role;
}
