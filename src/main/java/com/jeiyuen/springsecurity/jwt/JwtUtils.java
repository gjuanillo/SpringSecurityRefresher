package com.jeiyuen.springsecurity.jwt;

import java.security.Key;
import java.util.Date;

import jakarta.servlet.http.HttpServletRequest;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    @Value("${spring.app.jwtExpirationInMs}")
    private int jwtExpirationInMs;
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    // Get JWT from Header
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            // return the string starting after 'Bearer ' == 7
            return bearerToken.substring(7);
        }
        return null;
    }

    // Generate Token from Username
    public String generateTokenfromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date().getTime() + jwtExpirationInMs)))
                // Sign the token with the generated key
                .signWith(key())
                // Builds the token into string
                .compact();
    }

    // Get Username from JWT Token
    public String getUsernamefromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    // Generate Signing Key
    public Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    // Validate JWT
    public boolean validateJwtToken(String authToken){
        try {
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;

        } catch(MalformedJwtException e){
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch(ExpiredJwtException e) {
            logger.error("JWT token expired: {}", e.getMessage());
        } catch(UnsupportedJwtException e){
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch(IllegalArgumentException e){
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
