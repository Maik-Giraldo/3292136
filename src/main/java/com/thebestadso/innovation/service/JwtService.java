package com.thebestadso.innovation.service;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

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

    
}
