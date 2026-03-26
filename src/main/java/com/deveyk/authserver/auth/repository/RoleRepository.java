package com.deveyk.authserver.auth.repository;

import com.deveyk.authserver.auth.repository.entity.RoleEntity;
import com.deveyk.authserver.auth.repository.entity.RoleEntity.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<RoleEntity, String> {
    Optional<RoleEntity> findByName(RoleType roleType);
}
