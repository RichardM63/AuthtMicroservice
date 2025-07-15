package com.utp.auth_service.dto;

import com.utp.auth_service.domain.enums.Rol;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class RegistroUsuarioDTO {

    @Schema(description = "Nombre completo del usuario", example = "Juan Pérez")
    private String nombre;

    @Schema(description = "Correo electrónico del usuario", example = "juan.perez@utp.edu.pe")
    private String email;

    @Schema(description = "Contraseña del usuario", example = "miClaveSegura123")
    private String password;

    @Schema(description = "Rol del usuario", example = "DOCENTE")
    private Rol rol;
}