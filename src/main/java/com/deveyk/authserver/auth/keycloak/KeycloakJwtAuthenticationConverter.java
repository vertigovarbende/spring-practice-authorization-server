package com.deveyk.authserver.auth.keycloak;

import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String RESOURCE_ACCESS_CLAIM = "resource_access";
    private static final String ROLES_KEY = "roles";
    private static final String GROUPS_CLAIM = "groups";
    private static final String CLIENT_ID = "spring-app";

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.of(
                        jwtGrantedAuthoritiesConverter.convert(jwt).stream(),           // SCOPE_xxx
                        extractRealmRoles(jwt).stream(),                                // ROLE_xxx
                        extractClientRoles(jwt).stream(),                               // CLIENT_ROLE_xxx
                        extractGroups(jwt).stream()                                     // GROUP_xxx
                )
                .flatMap(s -> s)
                .collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities, extractPrincipalName(jwt));
    }

    /**
     * Extract realm roles from realm_access.roles claim
     * Maps to ROLE_xxx authorities (uppercase)
     */
    private Collection<GrantedAuthority> extractRealmRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim(REALM_ACCESS_CLAIM);
        if (realmAccess == null) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        Collection<String> roles = (Collection<String>) realmAccess.get(ROLES_KEY);
        if (roles == null) {
            return Collections.emptyList();
        }

        return roles.stream()
                .filter(role -> !role.startsWith("default-roles"))  // Filter out default Keycloak roles
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toList());
    }

    /**
     * Extract client roles from resource_access.{client}.roles claim
     * Maps to CLIENT_ROLE_xxx authorities
     */
    private Collection<GrantedAuthority> extractClientRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim(RESOURCE_ACCESS_CLAIM);
        if (resourceAccess == null) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(CLIENT_ID);
        if (clientAccess == null) {
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        Collection<String> roles = (Collection<String>) clientAccess.get(ROLES_KEY);
        if (roles == null) {
            return Collections.emptyList();
        }

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(
                        "CLIENT_ROLE_" + role.toUpperCase().replace("-", "_")))
                .collect(Collectors.toList());
    }

    /**
     * Extract groups from groups claim
     * Maps to GROUP_xxx authorities
     * /engineering/backend -> GROUP_ENGINEERING_BACKEND
     */
    private Collection<GrantedAuthority> extractGroups(Jwt jwt) {
        Collection<String> groups = jwt.getClaim(GROUPS_CLAIM);
        if (groups == null) {
            return Collections.emptyList();
        }

        return groups.stream()
                .map(group -> {
                    // /engineering/backend -> GROUP_ENGINEERING_BACKEND
                    String normalized = group.replace("/", "_")
                            .toUpperCase()
                            .replaceFirst("^_", "");  // Remove leading underscore
                    return new SimpleGrantedAuthority("GROUP_" + normalized);
                })
                .collect(Collectors.toList());
    }

    /**
     * Extract principal name from JWT
     * Uses preferred_username or falls back to subject (sub)
     */
    private String extractPrincipalName(Jwt jwt) {
        String preferredUsername = jwt.getClaimAsString("preferred_username");
        return preferredUsername != null ? preferredUsername : jwt.getSubject();
    }
}
