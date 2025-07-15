package com.utp.auth_service.domain.repository;

import com.utp.auth_service.domain.model.Usuario;

import java.util.Optional;

public interface UsuarioRepository {
    Usuario save(Usuario usuario);
    Optional<Usuario> findByEmail(String email);
}