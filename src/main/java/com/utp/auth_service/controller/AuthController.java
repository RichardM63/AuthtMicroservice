package com.utp.auth_service.controller;

import com.utp.auth_service.application.service.IAuthService;
import com.utp.auth_service.dto.JwtResponseDTO;
import com.utp.auth_service.dto.LoginDTO;
import com.utp.auth_service.dto.RegistroUsuarioDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final IAuthService authService;

    @Operation(
            summary = "Registra un nuevo usuario",
            description = "Crea un nuevo usuario con correo, contraseña y rol (e.g. ALUMNO o DOCENTE).",
            responses = @ApiResponse(
                    responseCode = "200",
                    description = "Usuario registrado exitosamente",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = JwtResponseDTO.class),
                            examples = @ExampleObject(value = """
                        {
                          "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                          "rol": "DOCENTE"
                        }
                        """)
                    )
            )
    )
    @PostMapping("/register")
    public ResponseEntity<JwtResponseDTO> register(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Datos para registrar un nuevo usuario",
                    required = true,
                    content = @Content(
                            schema = @Schema(implementation = RegistroUsuarioDTO.class),
                            examples = @ExampleObject(value = """
                        {
                          "correo": "ana.docente@utp.edu.pe",
                          "password": "12345678",
                          "rol": "DOCENTE"
                        }
                        """)
                    )
            )
            @RequestBody RegistroUsuarioDTO dto
    ) {
        return ResponseEntity.ok(authService.register(dto));
    }

    @Operation(
            summary = "Autentica a un usuario y genera un JWT",
            description = "Valida las credenciales del usuario y retorna un token JWT en caso de éxito.",
            responses = @ApiResponse(
                    responseCode = "200",
                    description = "Login exitoso",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = JwtResponseDTO.class),
                            examples = @ExampleObject(value = """
                        {
                          "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                          "rol": "ALUMNO"
                        }
                        """)
                    )
            )
    )
    @PostMapping("/login")
    public ResponseEntity<JwtResponseDTO> login(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Credenciales del usuario",
                    required = true,
                    content = @Content(
                            schema = @Schema(implementation = LoginDTO.class),
                            examples = @ExampleObject(value = """
                        {
                          "correo": "juan.alumno@utp.edu.pe",
                          "password": "password123"
                        }
                        """)
                    )
            )
            @RequestBody LoginDTO dto
    ) {
        return ResponseEntity.ok(authService.login(dto));
    }

    @Operation(
            summary = "Obtiene los datos del usuario autenticado",
            description = "A partir del JWT en el header Authorization, devuelve correo y rol.",
            responses = @ApiResponse(
                    responseCode = "200",
                    description = "Usuario autenticado",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = JwtResponseDTO.class),
                            examples = @ExampleObject(value = """
                        {
                          "token": "mismo JWT que recibiste",
                          "rol": "ALUMNO"
                        }
                        """)
                    )
            )
    )
    @GetMapping("/me")
    public ResponseEntity<JwtResponseDTO> getCurrentUser(
            @Parameter(description = "Token JWT del usuario", required = true, example = "Bearer eyJhbGciOiJIUzI1NiJ9...")
            HttpServletRequest request
    ) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().build();
        }
        String token = authHeader.substring(7);
        return ResponseEntity.ok(authService.getCurrentUser(token));
    }

    @Operation(
            summary = "Valida un token JWT y devuelve correo y rol",
            description = "Verifica si el token JWT es válido y devuelve detalles del usuario si es correcto.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Token válido",
                            content = @Content(
                                    mediaType = "application/json",
                                    examples = @ExampleObject(value = """
                        {
                          "valid": true,
                          "correo": "lucas.admin@utp.edu.pe",
                          "rol": "ADMIN"
                        }
                        """)
                            )
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Token no proporcionado o inválido",
                            content = @Content(
                                    mediaType = "application/json",
                                    examples = @ExampleObject(value = """
                        {
                          "valid": false,
                          "message": "Token no proporcionado"
                        }
                        """)
                            )
                    )
            }
    )
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        Map<String, Object> response = authService.validateToken(authHeader);

        boolean valid = (boolean) response.getOrDefault("valid", false);
        if (!valid) {
            int status = response.get("message").equals("Token no proporcionado") ? 400 : 401;
            return ResponseEntity.status(status).body(response);
        }

        return ResponseEntity.ok(response);
    }
}