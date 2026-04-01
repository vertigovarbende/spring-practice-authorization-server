package com.deveyk.authserver.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/api/public")
public class PublicController {

    @GetMapping("/hello")
    public ResponseEntity<Map<String, Object>> hello() {
        return ResponseEntity.ok(Map.of(
                "message", "Hello from public endpoint!",
                "timestamp", LocalDateTime.now(),
                "access", "No authentication required"
        ));
    }

    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> info() {
        return ResponseEntity.ok(Map.of(
                "application", "Spring Security Training",
                "session", "01 - Security Fundamentals & Spring Security Architecture",
                "version", "1.0.0",
                "timestamp", LocalDateTime.now()
        ));
    }

}
