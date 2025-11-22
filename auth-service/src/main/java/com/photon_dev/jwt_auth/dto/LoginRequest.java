package com.photon_dev.jwt_auth.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}
