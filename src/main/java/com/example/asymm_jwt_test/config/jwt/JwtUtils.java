package com.example.asymm_jwt_test.config.jwt;

import com.example.asymm_jwt_test.application_user.ApplicationUserRepository;
import com.example.asymm_jwt_test.application_user.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger( JwtUtils.class );

    @Value( "${app.jwtSecret}" )
    private String jwtSecret;

    @Value( "${app.jwtExpirationMs}" )
    private int jwtExpirationMs;

    @Value( "${app.jwtCookieName}" )
    private String jwtCookie;

    // get JWT from Cookies by Cookie name
    public String getJwtFromCookies( HttpServletRequest request ) {
        Cookie cookie = WebUtils.getCookie( request, jwtCookie );

        return cookie != null ? cookie.getValue() : null;
    }

    // generate a Cookie containing JWT from username, date, expiration, secret
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

    // return Cookie with null value (used for clean Cookie)
    public ResponseCookie getCleanJwtCookie() {
        return ResponseCookie.from( jwtCookie, null )
                .path( "/api" )
                .build();
    }

    // get username from JWT
    public String getUserNameFromJwtToken( String token ) {
        return Jwts
                .parser()
                .setSigningKey( key() )
                .build()
                .parseClaimsJws( token )
                .getBody()
                .getSubject();
    }

    private Key key() {
        return Keys.hmacShaKeyFor( Decoders.BASE64.decode( jwtSecret ) );
    }

    public String parseJwt( HttpServletRequest request ) {
        return getJwtFromCookies( request );
    }

    // validate a JWT with a secret
    public boolean validateJwtToken( String token ) {
        try {
            // build the object of JWTParser with parameter key() and compare with a token
            Jwts.parser().setSigningKey( key() ).build().parse( token );
            return true;
        } catch ( MalformedJwtException e ) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch ( ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch ( UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
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
                                .map( auth -> auth.getAuthority() ).collect( Collectors.toList()) )
                .issuedAt( new Date() )
                .expiration( new Date( (new Date()).getTime() + jwtExpirationMs ) )
                .signWith( Jwts.SIG.RS256, generateJwtKeyEncryption(  ) )
                .compact();
    }

    private PublicKey generateJwtKeyDecryption( String jwtPublicKey ) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
            byte[] keyBytes = Base64.decodeBase64( jwtPublicKey );
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec( keyBytes );

            return keyFactory.generatePublic( x509EncodedKeySpec );

        } catch ( NoSuchAlgorithmException | InvalidKeySpecException e ) {
            throw new RuntimeException( e );
        }
    }

    private PrivateKey generateJwtKeyEncryption( String jwtPrivateKey ) {

            try {
                KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
                byte[] keyBytes = Base64.decodeBase64( jwtPrivateKey );
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec( keyBytes );

                return keyFactory.generatePrivate( pkcs8EncodedKeySpec );

            } catch ( NoSuchAlgorithmException | InvalidKeySpecException e ) {
                throw new RuntimeException( e );
            }
        }

    private KeyPair getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "RSA" );
        keyPairGenerator.initialize( 2048 );

        return  keyPairGenerator.generateKeyPair();
    }
}

