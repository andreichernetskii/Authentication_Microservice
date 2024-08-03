package com.example.asymm_jwt_test.auth;

import com.example.asymm_jwt_test.application_user.request.LoginRequest;
import com.example.asymm_jwt_test.application_user.request.SignupRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for handling authentication-related requests
 */
@CrossOrigin( origins = "*", maxAge = 3600 )
@RestController
@RequestMapping( "/api/auth" )
public class AuthController {
    private final AuthService authService;

    public AuthController( AuthService authService ) {
        this.authService = authService;
    }

    // Endpoint for authenticating a user
    @PostMapping( "/signin" )
    public ResponseEntity<?> authenticateUser( @RequestBody LoginRequest loginRequest ) {
        return authService.authenticateUser( loginRequest );
    }

    // Endpoint for registering a new user
    @PostMapping( "/signup" )
    public ResponseEntity<?> registerUser( @RequestBody SignupRequest signUpRequest ) {
        return authService.registerUser( signUpRequest );
    }

    // Endpoint for logging out a user
    @PostMapping( "/signout" )
    public ResponseEntity<?> logoutUser( HttpServletRequest request ) {
        return authService.logoutUser( request );
    }

    @GetMapping( "/username" )
    public String getActualUserName() {
        return authService.getActualUserName();
    }
}
