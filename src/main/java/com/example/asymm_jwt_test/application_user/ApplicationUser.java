package com.example.asymm_jwt_test.application_user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

/**
 * Entity class representing the user table in the database with logins and passwords.
 */
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApplicationUser  {
    @Id
    private String email;
    private String password;
    @ElementCollection
    @Enumerated( EnumType.STRING )
    private Set<UserRole> roles = new HashSet<>();

    public ApplicationUser( String email, String password ) {
        this.email = email;
        this.password = password;
    }
}
