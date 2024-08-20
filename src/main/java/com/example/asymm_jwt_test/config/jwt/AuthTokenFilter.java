package com.example.asymm_jwt_test.config.jwt;

import com.example.asymm_jwt_test.application_user.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import org.slf4j.Logger;

@Component
@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {
    private final JwtUtils jwtUtils;
    private final UserDetailsServiceImpl userDetailsService;

    private static final Logger LOGGER = LoggerFactory.getLogger( AuthTokenFilter.class );

    @Override
    protected void doFilterInternal( HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain ) throws ServletException, IOException {

        try {

            String jwtToken = jwtUtils.parseJwt( request );

            if ( isJwtTokenValid( jwtToken ) ) {
                UsernamePasswordAuthenticationToken authentication = createAuthenticationFromUserToken( jwtToken );

                authentication.setDetails( new WebAuthenticationDetailsSource().buildDetails( request ) );

                SecurityContextHolder.getContext().setAuthentication( authentication );
            }
        } catch ( Exception e ) {
            LOGGER.error( "Cannot set user authentication: {}", e.getMessage() );
        }

        filterChain.doFilter( request, response );
    }

    private boolean isJwtTokenValid( String jwt ) {
        return jwt != null && jwtUtils.validateJwtToken( jwt );
    }

    private UsernamePasswordAuthenticationToken createAuthenticationFromUserToken( String jwt ) {
        String username = jwtUtils.getUserNameFromJwtToken( jwt );

        UserDetails userDetails = userDetailsService.loadUserByUsername( username );

        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }
}

