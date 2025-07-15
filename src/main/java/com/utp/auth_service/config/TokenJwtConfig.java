package com.utp.auth_service.config;

import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class TokenJwtConfig {

    public static final String SECRET = "clave-secreta-super-larga-para-jwt-segura-utp-auth-2025";
    public static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    public static final String PREFIX_TOKEN = "Bearer ";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_TYPE = "Content-Type";
    public static final String CONTENT_TYPE = "application/json";
}