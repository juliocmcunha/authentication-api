package org.juliocmcnha.auth2r.config;

import org.juliocmcnha.auth2r.domain.AppUser;
import org.juliocmcnha.auth2r.domain.OAuthClient;
import org.juliocmcnha.auth2r.domain.Role;
import org.juliocmcnha.auth2r.repository.OAuthClientRepository;
import org.juliocmcnha.auth2r.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.EnumSet;
import java.util.Set;

/**
 * Populates the in-memory database with demo identities on start-up.
 *
 * <p>Runs before the console demo (which is {@code @Order(Ordered.LOWEST_PRECEDENCE)}).
 *
 * <pre>
 * Users (password grant):
 *   alice / alice123   -> USER
 *   bob   / bob123     -> USER, MANAGER
 *   carol / carol123   -> USER, MANAGER, ADMIN
 *
 * Clients (client_credentials grant):
 *   demo-console / console-secret -> MANAGER  (scopes: api.read api.write)
 * </pre>
 */
@Component
@Order(1)
public class DataSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final OAuthClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    public DataSeeder(UserRepository userRepository,
                      OAuthClientRepository clientRepository,
                      PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (userRepository.count() == 0) {
            userRepository.save(user("alice", "alice123", EnumSet.of(Role.USER)));
            userRepository.save(user("bob", "bob123", EnumSet.of(Role.USER, Role.MANAGER)));
            userRepository.save(user("carol", "carol123", EnumSet.of(Role.USER, Role.MANAGER, Role.ADMIN)));
        }

        if (clientRepository.count() == 0) {
            clientRepository.save(new OAuthClient(
                    "demo-console",
                    passwordEncoder.encode("console-secret"),
                    EnumSet.of(Role.MANAGER),
                    Set.of("api.read", "api.write")));
        }
    }

    private AppUser user(String username, String rawPassword, Set<Role> roles) {
        return new AppUser(username, passwordEncoder.encode(rawPassword), roles);
    }
}
