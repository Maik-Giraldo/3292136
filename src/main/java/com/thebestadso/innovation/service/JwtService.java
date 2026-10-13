package com.thebestadso.innovation.service;

import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/**
 * Servicio que contiene los métodos para crear y validar un jwt
 * JwtService
 */
@Service
public class JwtService {

    /**
     * Clave secreta
     */
    @Value("${env.jwt.secret-key}")
    private String secretKey;

    /**
     * Expiración del token
     */
    @Value("${env.jwt.token-expiration}")
    private Long tokenExpiration;

    /**
     * Transforma la clave secreta (BASE64) a un objeto SecretKey
     * 
     * @return Firma secreta
     */
    private SecretKey getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generar jwt firmado
     * 
     * @param userId
     * @param username
     * @param rolId
     * @return jwt
     */
    public String generateToken(Long userId, String username, Long rolId) {
        return Jwts.builder()
                    .claims(Map.of("userId", userId)) // Claims personalizados, se deben mapear con llave valor (Map.of)
                    .claims(Map.of("rolId", rolId)) // Claims personalizados, se deben mapear con llave valor (Map.of)
                    .subject(username) // Claim obligatorio (A quién pertenece el token)
                    .issuedAt(new Date()) // Fecha de creación
                    .expiration(new Date(System.currentTimeMillis() + tokenExpiration)) // Fecha de expiración expresado en ms
                    .signWith(getSignKey()) // Firmar con (metodo de arriba getSignKey())
                    .compact(); // Unimos todo en una sola cadena separada por puntos (xxxxx.yyyyy.zzzzzz)
    }

    /**
     * Verifica si un token es válido y no ha sido manipulado
     * 
     * @param token jwt que se recibe en la request
     * @return true si la firma es correcta, false en caso contrario
     */
    public Boolean isTokenValid(String token) {
        try {
            Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token);
            return true;
        } catch (JwtException e) { // Si falla por jwt entra por acá y nos dice especificamente que fue lo que pasó
            e.printStackTrace();
            return false;
        } catch (Exception e) { // Si falla por cualquier otra cosa, él es el que lo atrapa
            e.printStackTrace();
            return false;
        }
    }

    
}