package com.example.asymm_jwt_test.config.jwt;

import com.example.asymm_jwt_test.application_user.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.DependsOn;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import java.security.*;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@DependsOn( "keyPairOnStartGenerator" )
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger( JwtUtils.class );
    private final KeyPairOnStartGenerator keyPairOnStartGenerator;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    @Value( "${app.jwtExpirationMs}" )
    private int jwtExpirationMs;

    @Value( "${app.jwtCookieName}" )
    private String jwtCookie;

    @PostConstruct
    private void setKeys() {
        publicKey = keyPairOnStartGenerator.getPublicKey();
        privateKey = keyPairOnStartGenerator.getPrivateKey();
    }

    public String getJwtFromCookies( HttpServletRequest request ) {
        Cookie cookie = WebUtils.getCookie( request, jwtCookie );
        return cookie != null ? cookie.getValue() : null;
    }

    public ResponseCookie generateJwtCookie( UserDetailsImpl userPrincipal ) {
        String jwt = generateTokenFromUsername( userPrincipal );

        return ResponseCookie
                .from( jwtCookie, jwt )
                .path( "/api" )
                .maxAge( 24 * 60 * 60 )
                .httpOnly( true )
                .secure( true )
                .build();
    }

    public ResponseCookie getCleanJwtCookie() {
        return ResponseCookie
                .from( jwtCookie, null )
                .path( "/api" )
                .build();
    }

    public String getUserNameFromJwtToken( String token ) {
        return Jwts
                .parser()
                .verifyWith( publicKey )
                .build()
                .parseSignedClaims( token )
                .getPayload()
                .getSubject();
    }

    public String parseJwt( HttpServletRequest request ) {
        return getJwtFromCookies( request );
    }

    public boolean validateJwtToken( String token ) {
        try {
            // build the object of JWTParser with parameter publicKey and compare with a token
            Jwts
                    .parser()
                    .verifyWith( publicKey )
                    .build()
                    .parse( token );

            return true;
        } catch ( SignatureException e ) {
            logger.error( "Invalid JWT signature: {}", e.getMessage() );
        } catch ( MalformedJwtException e ) {
            logger.error( "Invalid JWT token: {}", e.getMessage() );
        } catch ( ExpiredJwtException e ) {
            logger.error( "JWT token is expired: {}", e.getMessage() );
        } catch ( UnsupportedJwtException e ) {
            logger.error( "JWT token is unsupported: {}", e.getMessage() );
        } catch ( IllegalArgumentException e ) {
            logger.error( "JWT claims string is empty: {}", e.getMessage() );
        }

        return false;
    }

    private String generateTokenFromUsername( UserDetailsImpl userPrincipals ) {
        return Jwts
                .builder()
                .subject( userPrincipals.getUsername() )
                .claim( "role",
                        userPrincipals
                                .getAuthorities()
                                .stream()
                                .map( GrantedAuthority::getAuthority ).collect( Collectors.toList() ) )
                .issuedAt( new Date() )
                .expiration( new Date( ( new Date() ).getTime() + jwtExpirationMs ) )
                .signWith( privateKey, Jwts.SIG.RS256 )
                .compact();
    }
}

