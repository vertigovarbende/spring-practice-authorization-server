package com.deveyk.authserver.auth.controller;

import com.deveyk.authserver.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Manager Controller
 * <p>
 Endpoints accessible by managers only
 * <p>
 * Created for practice purposes.
 */
@RestController
@RequestMapping("/api/manager")
@RequiredArgsConstructor
public class ManagerController {

    private final UserRepository userRepository;

    @GetMapping("/reports")
    public ResponseEntity<Map<String, Object>> reports(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Manager reports",
                "username", authentication.getName(),
                "access", "Requires ROLE_MANAGER or ROLE_ADMIN",
                "timestamp", LocalDateTime.now()
        ));
    }

    @GetMapping("/team")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    public ResponseEntity<Map<String, Object>> team(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Team management",
                "manager", authentication.getName(),
                "access", "Method-level security with @PreAuthorize",
                "timestamp", LocalDateTime.now()
        ));
    }

    @GetMapping("/team/members")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    public ResponseEntity<Map<String, Object>> getTeamMembers(Authentication authentication) {
        List<Map<String, Object>> activeMembers = userRepository.findAll().stream()
                .filter(user -> !user.isDisabled() && !user.isAccountLocked())
                .map(user -> Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "email", user.getEmail(),
                        "fullName", (user.getFirstName() != null ? user.getFirstName() : "") + " " +
                                (user.getLastName() != null ? user.getLastName() : ""),
                        "status", "active",
                        "roles", user.getRoles().stream()
                                .map(role -> role.getName().name())
                                .collect(Collectors.toList())
                ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(Map.of(
                "teamMembers", activeMembers,
                "totalActiveMembers", activeMembers.size(),
                "manager", authentication.getName(),
                "timestamp", LocalDateTime.now()
        ));
    }


}
