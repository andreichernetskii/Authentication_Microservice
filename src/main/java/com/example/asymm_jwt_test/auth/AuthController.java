package com.example.asymm_jwt_test.auth;

import com.example.asymm_jwt_test.application_user.ApplicationUser;
import com.example.asymm_jwt_test.application_user.request.LoginRequest;
import com.example.asymm_jwt_test.application_user.request.SignupRequest;
import com.example.asymm_jwt_test.config.jwt.KeyPairOnStartGenerator;
import com.example.asymm_jwt_test.kafka.KafkaProducer;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller for handling authentication-related requests
 */
@CrossOrigin( origins = "*", maxAge = 3600 )
@RequiredArgsConstructor
@RestController
@RequestMapping( "/api/auth" )
public class AuthController {
    private final AuthService authService;

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
    public ResponseEntity<?> logoutUser() {
        return authService.logoutUser();
    }

    @GetMapping( "/username" )
    public String getActualUserName() {
        return authService.getActualUserName();
    }

    @GetMapping( "/all" )
    public List<ApplicationUser> getAllUsers() {
        return authService.getAllUsers();
    }
}
