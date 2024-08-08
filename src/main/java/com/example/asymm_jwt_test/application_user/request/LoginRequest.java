package com.example.asymm_jwt_test.application_user.request;

import lombok.Getter;

@Getter
public class LoginRequest {
    private String email;
    private String password;
}
