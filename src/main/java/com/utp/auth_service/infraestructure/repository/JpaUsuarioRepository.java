package com.utp.auth_service.infraestructure.repository;

import com.utp.auth_service.domain.model.Usuario;
import com.utp.auth_service.domain.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class JpaUsuarioRepository implements UsuarioRepository {

    private final SpringDataUsuarioRepository springDataRepo;

    @Override
    public Usuario save(Usuario usuario) {
        return springDataRepo.save(usuario);
    }

    @Override
    public Optional<Usuario> findByEmail(String email) {
        return springDataRepo.findByEmail(email);
    }
}