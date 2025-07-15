package com.utp.auth_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class LoginDTO {

    @Schema(description = "Correo electrónico del usuario", example = "admin@utp.edu.pe", required = true)
    private String email;

    @Schema(description = "Contraseña del usuario", example = "admin123", required = true)
    private String password;
}