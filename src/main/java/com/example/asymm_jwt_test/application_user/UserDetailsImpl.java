package com.example.asymm_jwt_test.application_user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * UserDetails implementation representing a user's details for authentication
 */
@AllArgsConstructor
public class UserDetailsImpl implements UserDetails {
    private String id;
    private String email;
    @JsonIgnore
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    public static UserDetailsImpl build(ApplicationUser applicationUser) {

        List<GrantedAuthority> authorities = getGrantedAuthorities( applicationUser );

        return new UserDetailsImpl(
                applicationUser.getId(),
                applicationUser.getEmail(),
                applicationUser.getPassword(),
                authorities
        );
    }

    private static List<GrantedAuthority> getGrantedAuthorities( ApplicationUser applicationUser ) {
        return applicationUser.getRoles().stream()
                .map( role -> new SimpleGrantedAuthority( role.name() ) )
                .collect( Collectors.toList() );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public String getId() {
        return id;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals( Object obj ) {
        if ( this == obj ) return true;
        if ( obj == null || getClass() != obj.getClass() ) return false;

        UserDetailsImpl user = ( UserDetailsImpl ) obj;

        return Objects.equals( email, user.email );
    }
}