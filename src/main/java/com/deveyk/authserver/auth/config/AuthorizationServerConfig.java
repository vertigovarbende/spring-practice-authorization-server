package com.deveyk.authserver.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
public class AuthorizationServerConfig {

    /**
     * Configures the security filter chain for the authorization server.
     * This method sets up the necessary components for handling OAuth2 authorization
     * and OpenID Connect (OIDC) requests, including exception handling and configuring
     * the OAuth2 resource server for JWT token validation.
     *
     * @param http an {@link HttpSecurity} object used to configure security settings.
     * @return a {@link SecurityFilterChain} configured for the authorization server.
     * @throws Exception if any error occurs while building the security configuration.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())   // to avoid the conflict between request matchers - best practice
                .with(authorizationServerConfigurer, authorizationServer ->
                        authorizationServer.oidc(Customizer.withDefaults()))
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    /**
     * Configures the default security filter chain for handling login and error paths.
     * This method ensures that any request matching the specified paths requires authentication
     * and sets up basic form login processing with default configurations.
     *
     * @param http an {@link HttpSecurity} object used to configure security settings.
     * @return a {@link SecurityFilterChain} configured for login and error handling paths.
     * @throws Exception if any error occurs while building the security configuration.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/login", "/error")
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    /**
     * Creates a {@link RegisteredClientRepository} bean to manage OAuth2 registered clients.
     *
     * This method configures a public client with predefined client ID, client secret,
     * supported authentication methods, authorization grant types, redirect URIs, scopes,
     * client settings, and token settings. The client is stored in-memory
     * for simplicity and demonstration purposes.
     *
     * @return a {@link RegisteredClientRepository} containing the predefined public client.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("public-client-id")
                .clientSecret("{noop}public-client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Add authorization grant type for authorization code
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // Add authorization grant type for refresh token
                .redirectUri("http://localhost:8080/authorized")
                .redirectUri("http://localhost:8080/login/oauth2/code/public-client-id")
                .scope("read")
                .scope("write")
                .scope("offline_access") // Support offline access through refresh tokens - to get refresh token
                .scope("openid") // OpenID Connect discovery - to get ID Token
                .scope("profile")
                .scope("email")
                // Customize client settings
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true) // Require consent from the resource owner upon client authorization
                        .requireProofKey(true) // to get PKCE (Proof Key for Code Exchange)
                        .build())
                // Customize token settings
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofHours(1)) // Access token will expire in 1 day
                        .refreshTokenTimeToLive(Duration.ofDays(7)) // refresh token will expire in 1 week
                        .reuseRefreshTokens(false)
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(publicClient);
    }

    /**
     * Creates a JWKSource bean used to manage JSON Web Keys (JWKs) necessary for signing and verifying
     * JSON Web Tokens (JWTs) in the authorization server.
     *
     * This method generates an RSA key pair, constructs a corresponding JWK, and creates an immutable
     * JWK set containing the generated key. The JWKSource is subsequently used by the authorization
     * server for cryptographic operations such as token signing.
     *
     * @return a {@link JWKSource} of {@link SecurityContext} providing access to the generated JWK set.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Creates a {@link JwtDecoder} bean responsible for decoding JSON Web Tokens (JWTs).
     * This method leverages a provided {@link JWKSource} to validate and process JWTs
     * within the authorization server.
     *
     * @param jwkSource a {@link JWKSource} of {@link SecurityContext} containing the JSON Web Keys
     *                  used for cryptographic operations such as signing and verifying JWTs.
     * @return a {@link JwtDecoder} instance configured to decode and validate JWT tokens.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Configures custom settings for the authorization server.
     *
     * The method creates an {@link AuthorizationServerSettings} bean using the builder pattern.
     * It sets the issuer URI required for the authorization server's operational context.
     *
     * @return an {@link AuthorizationServerSettings} instance configured with the custom issuer URI.
     */
    @Bean
    public AuthorizationServerSettings customAuthorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8080")
                .build();
    }

    /**
     * Customizes the encoding of JWT tokens by adding additional claims based on the authenticated user's principal.
     * Specifically, this method extracts the roles (authorities) of the authenticated user and includes them
     * as a "roles" claim in the JWT.
     *
     * @return an {@link OAuth2TokenCustomizer} implementation that modifies the {@link JwtEncodingContext}
     *         to include the user's roles in the generated JWT.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            if (context.getPrincipal() != null) {
                context.getClaims().claims(claims -> claims.put("roles",
                        context.getPrincipal().getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toSet())));
            }
        };
    }

    /**
     * Generates an RSA key pair.
     * The key pair is generated using the RSA algorithm with a key size of 2048 bits.
     *
     * @return a {@link KeyPair} containing the generated RSA public and private keys
     * @throws IllegalStateException if the key generation process fails
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
