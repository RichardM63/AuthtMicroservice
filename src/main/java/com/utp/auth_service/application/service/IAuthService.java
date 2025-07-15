package com.utp.auth_service.application.service;

import com.utp.auth_service.dto.JwtResponseDTO;
import com.utp.auth_service.dto.LoginDTO;
import com.utp.auth_service.dto.RegistroUsuarioDTO;

import java.util.Map;

public interface IAuthService {
    JwtResponseDTO register(RegistroUsuarioDTO dto);
    JwtResponseDTO login(LoginDTO dto);
    JwtResponseDTO getCurrentUser(String token);
    Map<String, Object> validateToken(String authHeader);
}
