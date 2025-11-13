package com.example.auth_service.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpirationMs;

    @Value("${jwt.refresh.expiration:604800000}") // 7 days default
    private int jwtRefreshExpirationMs;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    /**
     * Generate standard access token with user information
     */
    public String generateJwtToken(Authentication authentication, Long userId) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();

        // Extract roles from authorities
        String roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("roles", roles);
        claims.put("tokenType", "ACCESS");

        return buildToken(userPrincipal.getUsername(), claims, jwtExpirationMs);
    }

    /**
     * Generate token with custom claims for special cases
     */
    public String generateCustomToken(String username, Long userId, String roles,
                                      boolean isTemporary, String tokenPurpose) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("roles", roles);
        claims.put("isTemporary", isTemporary);
        claims.put("tokenType", tokenPurpose); // e.g., "PASSWORD_RESET", "EMAIL_VERIFICATION", "ADMIN_ACTION"

        // Use shorter expiration for temporary tokens
        int expiration = isTemporary ? 3600000 : jwtExpirationMs; // 1 hour for temporary

        return buildToken(username, claims, expiration);
    }

    /**
     * Generate refresh token (longer expiration, minimal claims)
     */
    public String generateRefreshToken(String username, Long userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("tokenType", "REFRESH");

        return buildToken(username, claims, jwtRefreshExpirationMs);
    }

    /**
     * Core method to build JWT token
     */
    private String buildToken(String subject, Map<String, Object> claims, int expirationMs) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Get username from token
     */
    public String getUserNameFromJwtToken(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    /**
     * Get userId from token
     */
    public Long getUserIdFromJwtToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get("userId", Long.class);
    }

    /**
     * Get roles from token
     */
    public String getRolesFromJwtToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get("roles", String.class);
    }

    /**
     * Get token type (ACCESS, REFRESH, PASSWORD_RESET, etc.)
     */
    public String getTokenType(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get("tokenType", String.class);
    }

    /**
     * Check if token is temporary
     */
    public Boolean isTemporaryToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.get("isTemporary", Boolean.class);
    }

    /**
     * Get all claims from token
     */
    private Claims getClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Validate token with enhanced checks
     */
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("JWT token validation error: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Validate token for specific purpose
     */
    public boolean validateTokenForPurpose(String token, String expectedPurpose) {
        if (!validateJwtToken(token)) {
            return false;
        }

        try {
            String tokenType = getTokenType(token);
            return expectedPurpose.equals(tokenType);
        } catch (Exception e) {
            logger.error("Error validating token purpose: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if token is about to expire (within 5 minutes)
     */
    public boolean isTokenExpiringSoon(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            Date expiration = claims.getExpiration();
            Date now = new Date();
            long timeUntilExpiration = expiration.getTime() - now.getTime();
            return timeUntilExpiration < 300000; // 5 minutes
        } catch (Exception e) {
            logger.error("Error checking token expiration: {}", e.getMessage());
            return true; // Treat errors as expiring
        }
    }
}