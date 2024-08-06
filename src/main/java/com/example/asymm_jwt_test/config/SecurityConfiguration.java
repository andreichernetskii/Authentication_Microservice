package com.example.asymm_jwt_test.config;

import com.example.asymm_jwt_test.application_user.UserDetailsServiceImpl;
import com.example.asymm_jwt_test.config.jwt.AuthEntryPointJwt;
import com.example.asymm_jwt_test.config.jwt.AuthTokenFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security configuration class that defines security-related beans and settings.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final UserDetailsServiceImpl userDetailsService;
    private final AuthEntryPointJwt unauthorizedHandle;
    private final AuthTokenFilter authTokenFilter;

    // Creates an instance of the DaoAuthenticationProvider bean.
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService( userDetailsService );
        authProvider.setPasswordEncoder( passwordEncoder() );

        return authProvider;
    }

    // Creates an instance of the AuthenticationManager bean.
    @Bean
    public AuthenticationManager authenticationManager( AuthenticationConfiguration authConfig ) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // Creates an instance of the BCryptPasswordEncoder bean.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Configures the security filter chain.
    @Bean
    public SecurityFilterChain filterChain( HttpSecurity http ) throws Exception {

        http
                .csrf( AbstractHttpConfigurer::disable )
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers( "/api/auth/signin", "/api/auth/signup" ).permitAll()
                                .anyRequest().authenticated()
                )
                .exceptionHandling( exception -> exception.authenticationEntryPoint( unauthorizedHandle ) )
                .sessionManagement( session -> session.sessionCreationPolicy( SessionCreationPolicy.STATELESS ) )
                .authenticationProvider( authenticationProvider() )

        ;

        http.addFilterBefore( authTokenFilter, UsernamePasswordAuthenticationFilter.class );

        return http.build();
    }
}
