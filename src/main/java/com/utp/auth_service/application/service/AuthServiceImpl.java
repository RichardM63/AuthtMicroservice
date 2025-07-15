package com.utp.auth_service.application.service;

import com.utp.auth_service.config.TokenJwtConfig;
import com.utp.auth_service.domain.enums.Rol;
import com.utp.auth_service.domain.model.Usuario;
import com.utp.auth_service.domain.repository.UsuarioRepository;
import com.utp.auth_service.dto.JwtResponseDTO;
import com.utp.auth_service.dto.LoginDTO;
import com.utp.auth_service.dto.RegistroUsuarioDTO;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Override
    public JwtResponseDTO register(RegistroUsuarioDTO dto) {
        if (usuarioRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new RuntimeException("El correo ya está registrado.");
        }

        Usuario usuario = new Usuario();
        usuario.setNombre(dto.getNombre());
        usuario.setEmail(dto.getEmail());
        usuario.setPassword(passwordEncoder.encode(dto.getPassword()));
        usuario.setRol(dto.getRol() != null ? dto.getRol() : Rol.ESTUDIANTE);

        usuarioRepository.save(usuario);

        String token = generarToken(usuario.getEmail(), usuario.getRol().name());

        return new JwtResponseDTO(token, usuario.getNombre(), usuario.getRol().name());
    }

    @Override
    public JwtResponseDTO login(LoginDTO dto) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getPassword())
        );

        Usuario usuario = usuarioRepository.findByEmail(dto.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        String token = generarToken(usuario.getEmail(), usuario.getRol().name());

        return new JwtResponseDTO(token, usuario.getNombre(), usuario.getRol().name());
    }

    @Override
    public JwtResponseDTO getCurrentUser(String token) {
        String email = extraerEmailDesdeToken(token);

        Usuario usuario = usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        return new JwtResponseDTO(token, usuario.getNombre(), usuario.getRol().name());
    }

    @Override
    public Map<String, Object> validateToken(String authHeader) {
        Map<String, Object> response = new HashMap<>();

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.put("valid", false);
            response.put("message", "Token no proporcionado");
            return response;
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(TokenJwtConfig.SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String correo = claims.getSubject();
            List<String> roles = (List<String>) claims.get("roles");

            response.put("valid", true);
            response.put("correo", correo);
            response.put("rol", roles != null && !roles.isEmpty() ? roles.get(0) : null);

            return response;

        } catch (ExpiredJwtException e) {
            response.put("valid", false);
            response.put("message", "Token expirado");
            return response;
        } catch (JwtException e) {
            response.put("valid", false);
            response.put("message", "Token inválido");
            return response;
        }
    }

    private String generarToken(String email, String rol) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", Collections.singletonList(rol));

        return Jwts.builder()
                .setClaims(claims) // primero los claims
                .setSubject(email) // después el subject
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 4))
                .signWith(TokenJwtConfig.SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    private String extraerEmailDesdeToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(TokenJwtConfig.SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
