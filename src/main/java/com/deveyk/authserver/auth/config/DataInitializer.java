package com.deveyk.authserver.auth.config;

import com.deveyk.authserver.auth.repository.entity.RoleEntity;
import com.deveyk.authserver.auth.repository.entity.RoleEntity.RoleType;
import com.deveyk.authserver.auth.repository.entity.UserEntity;
import com.deveyk.authserver.auth.repository.RoleRepository;
import com.deveyk.authserver.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
public class DataInitializer {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    public CommandLineRunner initData(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder) {

        return args -> {
            log.info("Initializing database with test data...");

            // Create roles if they don't exist
            RoleEntity roleUser = createRoleIfNotExists(roleRepository, RoleType.ROLE_USER,
                    "Standard user role with basic permissions");
            RoleEntity roleManager = createRoleIfNotExists(roleRepository, RoleType.ROLE_MANAGER,
                    "Manager role with elevated permissions");
            RoleEntity roleAdmin = createRoleIfNotExists(roleRepository, RoleType.ROLE_ADMIN,
                    "Administrator role with full permissions");

            // Create users if they don't exist
            createUserIfNotExists(userRepository, passwordEncoder,
                    "user", "password", "user@example.com",
                    "John", "Doe", Set.of(roleUser));

            createUserIfNotExists(userRepository, passwordEncoder,
                    "manager", "password", "manager@example.com",
                    "Jane", "Smith", Set.of(roleUser, roleManager));

            createUserIfNotExists(userRepository, passwordEncoder,
                    "admin", "password", "admin@example.com",
                    "Admin", "User", Set.of(roleUser, roleManager, roleAdmin));

            log.info("Database initialization completed!");
            log.info("Available users:");
            log.info("  - username: user, password: password (ROLE_USER)");
            log.info("  - username: manager, password: password (ROLE_USER, ROLE_MANAGER)");
            log.info("  - username: admin, password: password (ROLE_USER, ROLE_MANAGER, ROLE_ADMIN)");
        };
    }

    private RoleEntity createRoleIfNotExists(RoleRepository roleRepository, RoleType roleType, String description) {
        return roleRepository.findByName(roleType)
                .orElseGet(() -> {
                    RoleEntity role = RoleEntity.builder()
                            .name(roleType)
                            .description(description)
                            .build();
                    role = roleRepository.save(role);
                    log.info("Created role: {}", roleType);
                    return role;
                });
    }

    private void createUserIfNotExists(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            String username,
            String password,
            String email,
            String firstName,
            String lastName,
            Set<RoleEntity> roles) {

        if (!userRepository.existsByUsername(username)) {
            UserEntity user = UserEntity.builder()
                    .username(username)
                    .password(passwordEncoder.encode(password))
                    .email(email)
                    .firstName(firstName)
                    .lastName(lastName)
                    .build();
            user.setRoles(roles);
            userRepository.save(user);
            log.info("Created user: {} with roles: {}", username, roles);
        }
    }
}
