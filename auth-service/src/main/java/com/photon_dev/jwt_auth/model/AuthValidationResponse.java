package com.photon_dev.jwt_auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthValidationResponse {
    private String userId;
    private String roles;
}