package com.example.asymm_jwt_test.application_user.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@AllArgsConstructor
@Getter
public class UserInfoResponse {
    private String email;
    private List<String> roles;

    public void setEmail(String email) {
        this.email = email;
    }
}
