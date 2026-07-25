package org.juliocmcnha.auth2r;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the OAuth2 + Role-Based Access Control demo.
 *
 * <p>The single Spring Boot application plays two OAuth2 roles at once:
 * <ul>
 *   <li><b>Authorization Server (lightweight)</b> &mdash; the {@code /oauth2/token}
 *       endpoint issues signed JWT access tokens for the {@code password} and
 *       {@code client_credentials} grants, and {@code /oauth2/jwks} publishes the
 *       public key used to verify them.</li>
 *   <li><b>Resource Server</b> &mdash; the {@code /api/**} endpoints are protected
 *       with Spring Security's OAuth2 resource-server support and enforce access by
 *       role (USER / MANAGER / ADMIN) and by scope.</li>
 * </ul>
 */
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
