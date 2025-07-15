package com.utp.auth_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtResponseDTO {

    @Schema(description = "Token JWT generado", example = "eyJhbGciOiJIUzI1NiIsInR...")
    private String token;

    @Schema(description = "Correo electrónico del usuario", example = "juan.perez@utp.edu.pe")
    private String email;

    @Schema(description = "Rol del usuario", example = "DOCENTE")
    private String rol;
}