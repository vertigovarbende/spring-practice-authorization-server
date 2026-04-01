package com.deveyk.authserver.auth.controller;

import com.deveyk.authserver.auth.repository.UserRepository;
import com.deveyk.authserver.auth.repository.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * Admin Controller
 * <p>
 Endpoints accessible by administrators only
 * <p>
 * Created for practice purposes.
 */
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserRepository userRepository;

    @GetMapping("/users")
    public ResponseEntity<Map<String, Object>> getAllUsers(Authentication authentication) {
        List<Map<String, Object>> users = userRepository.findAll().stream()
                .map(user -> Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "email", user.getEmail(),
                        "enabled", user.isDisabled(),
                        "roles", user.getRoles().stream()
                                .map(role -> role.getName().name())
                                .collect(Collectors.toList())
                ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(Map.of(
                "users", users,
                "admin", authentication.getName(),
                "timestamp", LocalDateTime.now()
        ));
    }

    @GetMapping("/users/search")
    public ResponseEntity<Map<String, Object>> getUserByUsername(@RequestParam String username, Authentication authentication) {
        return userRepository.findByUsername(username)
                .map(user -> ResponseEntity.ok(Map.of(
                        "user", Map.of(
                                "id", user.getId(),
                                "username", user.getUsername(),
                                "email", user.getEmail(),
                                "firstName", user.getFirstName(),
                                "lastName", user.getLastName(),
                                "disabled", user.isDisabled()
                        ),
                        "admin", authentication.getName(),
                        "timestamp", LocalDateTime.now()
                )))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/system")
    public ResponseEntity<Map<String, Object>> systemInfo(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "System information",
                "access", "Admin only - Method-level security",
                "admin", authentication.getName(),
                "javaVersion", System.getProperty("java.version"),
                "osName", System.getProperty("os.name"),
                "timestamp", LocalDateTime.now()
        ));
    }

    @GetMapping("/users/stats")
    public ResponseEntity<Map<String, Object>> getUserStats(Authentication authentication) {
        List<UserEntity> allUsers = userRepository.findAll();

        long totalUsers = allUsers.size();
        long activeUsers = allUsers.stream().filter(user -> !user.isDisabled()).count();
        long disabledUsers = allUsers.stream().filter(UserEntity::isDisabled).count();
        long expiredUsers = allUsers.stream().filter(UserEntity::isAccountExpired).count();
        long lockedUsers = allUsers.stream().filter(UserEntity::isAccountLocked).count();

        return ResponseEntity.ok(Map.of(
                "stats", Map.of(
                        "totalUsers", totalUsers,
                        "activeUsers", activeUsers,
                        "disabledUsers", disabledUsers,
                        "expiredUsers", expiredUsers,
                        "lockedUsers", lockedUsers
                ),
                "admin", authentication.getName(),
                "timestamp", LocalDateTime.now()
        ));
    }


}
