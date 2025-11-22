package com.photon_dev.jwt_auth.service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class JwtService {
    @Value("${security.jwt.secret-key}")
    private String secret_key;

    @Value("${security.jwt.expiration-time}")
    private long token_duration;

    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (Exception e) {
            log.error("Erreur lors de l'extraction du nom d'utilisateur: {}", e.getMessage());
            throw new JwtException("Impossible d'extraire le nom d'utilisateur du token", e);
        }
    }

    public String extractRoles(String token) {
        try {
            return extractClaim(token, claims -> claims.get("roles", String.class));
        } catch (Exception e) {
            log.error("Erreur lors de l'extraction du nom d'utilisateur: {}", e.getMessage());
            throw new JwtException("Impossible d'extraire le nom d'utilisateur du token", e);
        }
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(Authentication authentication) {
        String username = authentication.getName();
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + token_duration);

        return Jwts.builder()
                .setSubject(username)
                .claim("roles", authorities)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .setIssuer("your-app")
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token) // JWS pour les tokens signés
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.warn("Token expiré: {}", e.getMessage());
            throw new JwtException("Token expiré", e);
        } catch (UnsupportedJwtException e) {
            log.warn("Token non supporté: {}", e.getMessage());
            throw new JwtException("Format de token non supporté", e);
        } catch (MalformedJwtException e) {
            log.warn("Token malformé: {}", e.getMessage());
            throw new JwtException("Token malformé", e);
        } catch (SecurityException e) {
            log.warn("Signature du token invalide: {}", e.getMessage());
            throw new JwtException("Signature invalide", e);
        } catch (IllegalArgumentException e) {
            log.warn("Token vide ou null: {}", e.getMessage());
            throw new JwtException("Token vide", e);
        } catch (Exception e) {
            log.error("Erreur lors du parsing du token: {}", e.getMessage());
            throw new JwtException("Erreur de validation du token", e);
        }
    }

    private Key getSignInKey() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secret_key);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            log.error("Erreur lors de la création de la clé de signature: {}", e.getMessage());
            throw new IllegalStateException("Clé secrète invalide", e);
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        } catch (Exception e) {
            log.warn("Validation du token échouée: {}", e.getMessage());
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            log.warn("Erreur lors de la vérification d'expiration: {}", e.getMessage());
            return true; // Si on ne peut pas vérifier, considérer comme expiré
        }
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}