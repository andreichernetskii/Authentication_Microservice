package com.example.asymm_jwt_test.application_user;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.HashSet;
import java.util.Set;

/**
 * Entity class representing the user table in the database with logins and passwords.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Document
public class ApplicationUser  {
    @Id
    private String email;
    private String password;
    private Set<UserRole> roles = new HashSet<>();

    public ApplicationUser( String email, String password ) {
        this.email = email;
        this.password = password;
    }
}
