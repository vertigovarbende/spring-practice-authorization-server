package com.deveyk.authserver.auth.repository.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Enumerated(EnumType.STRING)
    private RoleType name;

    private String description;


    public enum RoleType {
        ROLE_USER,
        ROLE_MANAGER,
        ROLE_ADMIN
    }
}
