package com.deveyk.authserver.auth.config;

import com.deveyk.authserver.auth.keycloak.KeycloakJwtAuthenticationConverter;
import com.deveyk.authserver.auth.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final KeycloakJwtAuthenticationConverter keycloakConverter;

    @Bean
    @Order(1)
    public SecurityFilterChain oauth2LoginFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/auth/**", "/oauth2/**", "/login/**", "/logout")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/login").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/auth/success", true)
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/auth/login")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                // Disable CSRF for stateless API
                .csrf(csrf -> csrf.disable())

                // Authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers("/api/public/**").permitAll()

                        // Realm role-based authorization (Keycloak realm roles)
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/api/user/**").hasRole("USER")

                        // Client role-based authorization (Keycloak client roles)
                        .requestMatchers("/api/resource/read/**").hasAuthority("CLIENT_ROLE_API_READ")
                        .requestMatchers("/api/resource/write/**").hasAuthority("CLIENT_ROLE_API_WRITE")
                        .requestMatchers("/api/resource/admin/**").hasAuthority("CLIENT_ROLE_API_ADMIN")

                        // Group-based authorization (Keycloak groups)
                        .requestMatchers("/api/engineering/**").hasAnyAuthority(
                                "GROUP_ENGINEERING",
                                "GROUP_ENGINEERING_BACKEND",
                                "GROUP_ENGINEERING_FRONTEND"
                        )
                        .requestMatchers("/api/management/**").hasAuthority("GROUP_MANAGEMENT")

                        // Claims demo endpoints
                        .requestMatchers("/api/claims/**").authenticated()

                        // All other requests require authentication
                        .anyRequest().authenticated()
                )

                // OAuth2 Resource Server with Keycloak JWT validation
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(keycloakConverter)
                        )
                )

                // Stateless session management (JWT-based)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }


    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}

