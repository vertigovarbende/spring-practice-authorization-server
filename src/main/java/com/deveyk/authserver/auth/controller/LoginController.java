package com.deveyk.authserver.auth.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

/**
 * OAuth2 Login Flow Controller
 *
 * Demonstrates browser-based OAuth2/OIDC login with Keycloak:
 * 1. User visits /auth/login
 * 2. Redirects to Keycloak login page
 * 3. After login, redirects back with tokens
 * 4. Shows token information
 */
@Controller
public class LoginController {

    @GetMapping("/auth/login")
    public String login() {
        return "redirect:/oauth2/authorization/keycloak";
    }

    @GetMapping("/auth/success")
    public String successPage(@AuthenticationPrincipal OidcUser oidcUser, Model model) {
        if (oidcUser == null) {
            return "login-required";
        }
        model.addAttribute("username", oidcUser.getPreferredUsername());
        model.addAttribute("email", oidcUser.getEmail());
        model.addAttribute("idToken", oidcUser.getIdToken().getTokenValue());
        return "success";
    }


    @GetMapping("/auth/logout")
    public String logout() {
        return "redirect:/logout";
    }

    @GetMapping("/auth/token")
    public Map<String, Object> tokenInfo(@AuthenticationPrincipal OidcUser oidcUser) {
        Map<String, Object> response = new HashMap<>();

        if (oidcUser == null) {
            response.put("error", "Not authenticated");
            response.put("login_url", "/auth/login");
            return response;
        }

        // User info
        response.put("username", oidcUser.getPreferredUsername());
        response.put("email", oidcUser.getEmail());
        response.put("name", oidcUser.getFullName());

        // Tokens
        response.put("id_token", oidcUser.getIdToken().getTokenValue());
        response.put("access_token", oidcUser.getAttribute("access_token"));

        // All claims from ID token
        response.put("claims", oidcUser.getClaims());

        // Token metadata
        response.put("issuer", oidcUser.getIssuer());
        response.put("subject", oidcUser.getSubject());
        response.put("issued_at", oidcUser.getIssuedAt());
        response.put("expires_at", oidcUser.getExpiresAt());

        // Keycloak specific claims
        response.put("realm_access", oidcUser.getAttribute("realm_access"));
        response.put("resource_access", oidcUser.getAttribute("resource_access"));
        response.put("groups", oidcUser.getAttribute("groups"));

        return response;
    }

}
