package com.example.asymm_jwt_test.application_user.request;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class SignupRequest {
    private String email;
    private Set<String> role;
    private String password;
}
