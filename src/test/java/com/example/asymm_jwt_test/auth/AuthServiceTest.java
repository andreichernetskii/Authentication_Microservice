package com.example.asymm_jwt_test.auth;

import com.example.asymm_jwt_test.application_user.ApplicationUser;
import com.example.asymm_jwt_test.application_user.ApplicationUserRepository;
import com.example.asymm_jwt_test.application_user.UserDetailsImpl;
import com.example.asymm_jwt_test.application_user.request.LoginRequest;
import com.example.asymm_jwt_test.application_user.request.SignupRequest;
import com.example.asymm_jwt_test.application_user.response.MessageResponse;
import com.example.asymm_jwt_test.application_user.response.UserInfoResponse;
import com.example.asymm_jwt_test.config.jwt.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith( MockitoExtension.class )
class AuthServiceTest {
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private ApplicationUserRepository applicationUserRepository;
    @Mock
    private PasswordEncoder encoder;
    @Mock
    private JwtUtils jwtUtils;
    @Mock
    private Authentication authentication;
    @Mock
    private SecurityContext securityContext;
    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext( securityContext );
    }

    @Test
    void getLoggedUserTest_Success() {
        UserDetailsImpl userDetails = mock( UserDetailsImpl.class );

        when( securityContext.getAuthentication() ).thenReturn( authentication );
        when( authentication.getPrincipal() ).thenReturn( userDetails );
        when( userDetails.getUsername() ).thenReturn( "test@user" );

        ApplicationUser user = new ApplicationUser();
        when( applicationUserRepository.findById( "test@user" ) ).thenReturn( Optional.of( user ) );

        ApplicationUser loggedUser = authService.getLoggedUser();

        assertEquals( user, loggedUser );
    }

    @Test
    void getLoggedUserTest_Failed_UserNotLogged() {
        when( securityContext.getAuthentication() ).thenReturn( null );

        assertThrows( AuthenticationException.class, () -> authService.getLoggedUser() );
    }

    @Test
    void authenticateUserTest() {
        LoginRequest loginRequest = mock( LoginRequest.class );

        when( loginRequest.getEmail() ).thenReturn( "test@user" );
        when( loginRequest.getPassword() ).thenReturn( "password" );

        when( authenticationManager.authenticate( any( UsernamePasswordAuthenticationToken.class ) ) )
                .thenReturn( authentication );

        UserDetailsImpl userDetails = mock( UserDetailsImpl.class );

        when( authentication.getPrincipal() ).thenReturn( userDetails );
        when( jwtUtils.generateJwtCookie( any( UserDetailsImpl.class ) ) )
                .thenReturn( ResponseCookie.from( "jwt", "token" ).build() );
        when( userDetails.getUsername() ).thenReturn( "test@user" );
        when( userDetails.getAuthorities() )
                .thenAnswer( invocation -> List.of( new SimpleGrantedAuthority( "ROLE_USER" ) ) );

        ResponseEntity<Object> response = authService.authenticateUser( loginRequest );

        assertNotNull( response );
        assertTrue( response.getHeaders().containsKey( HttpHeaders.SET_COOKIE ) );
        assertEquals( "test@user", ( ( UserInfoResponse ) response.getBody() ).getEmail() );
    }

    @Test
    void registerUserTest_Success() {
        SignupRequest signupRequest = mock( SignupRequest.class );

        when( signupRequest.getEmail() ).thenReturn( "test@user" );
        when( signupRequest.getPassword() ).thenReturn( "password" );
        when( signupRequest.getRole() ).thenReturn( Set.of( "ROLE_USER" ) );

        when( applicationUserRepository.existsByEmail( "test@user" ) ).thenReturn( false );
        when( encoder.encode( "password" ) ).thenReturn( "encodedPassword" );
        when( applicationUserRepository.save( any( ApplicationUser.class ) ) ).thenReturn( new ApplicationUser() );

        ResponseEntity<Object> response = authService.registerUser( signupRequest );

        assertNotNull( response );
        assertEquals( "User registered successfully!", ( ( MessageResponse ) response.getBody() ).getMessage() );
    }

    @Test
    void registerUserTest_Failed_EmailTaken() {
        SignupRequest signupRequest = mock( SignupRequest.class );

        when( signupRequest.getEmail() ).thenReturn( "test@user" );
        when( applicationUserRepository.existsByEmail( "test@user" ) ).thenReturn( true );

        ResponseEntity<Object> response = authService.registerUser( signupRequest );

        assertNotNull( response );
        assertEquals( "Error: Email is already taken!", ( ( MessageResponse ) response.getBody() ).getMessage() );
    }

    @Test
    void logoutUserTest() {
        when( jwtUtils.getCleanJwtCookie() ).thenReturn( ResponseCookie.from( "jwt", "" ).build() );

        ResponseEntity<Object> response = authService.logoutUser();

        assertNotNull( response );
        assertTrue( response.getHeaders().containsKey( HttpHeaders.SET_COOKIE ) );
        assertEquals( "You've been signed out!", ( ( MessageResponse ) response.getBody() ).getMessage() );
    }

    @Test
    void getActualUserName() {
    }

    @Test
    void getAllUsersTest() {
        List<ApplicationUser> users = Arrays.asList( new ApplicationUser(), new ApplicationUser() );
        when( applicationUserRepository.findAll() ).thenReturn( users );

        List<ApplicationUser> result = authService.getAllUsers();

        assertEquals( users.size(), result.size() );
    }
}