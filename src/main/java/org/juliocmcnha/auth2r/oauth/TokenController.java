package org.juliocmcnha.auth2r.oauth;

import org.juliocmcnha.auth2r.domain.OAuthClient;
import org.juliocmcnha.auth2r.domain.Role;
import org.juliocmcnha.auth2r.repository.OAuthClientRepository;
import org.juliocmcnha.auth2r.security.JwtTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * A minimal OAuth2 token endpoint.
 *
 * <p>Supports two grant types:
 * <ul>
 *   <li>{@code password} &mdash; resource-owner credentials, used by the demo console
 *       to log a user in and receive a role-carrying JWT. (Note: the password grant is
 *       discouraged in OAuth 2.1 for public clients; it is used here because it is the
 *       clearest way to demonstrate a user &rarr; token &rarr; role-protected-API flow
 *       from a console. See the README for the authorization-code alternative.)</li>
 *   <li>{@code client_credentials} &mdash; machine-to-machine access for a registered
 *       client, authenticated with HTTP Basic or form parameters.</li>
 * </ul>
 */
@RestController
public class TokenController {

    private final AuthenticationManager authenticationManager;
    private final OAuthClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService tokenService;

    public TokenController(AuthenticationManager authenticationManager,
                           OAuthClientRepository clientRepository,
                           PasswordEncoder passwordEncoder,
                           JwtTokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
    }

    @PostMapping(value = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public TokenResponse token(
            @RequestParam("grant_type") String grantType,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "client_id", required = false) String clientIdParam,
            @RequestParam(value = "client_secret", required = false) String clientSecretParam,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {

        return switch (grantType) {
            case "password" -> passwordGrant(username, password);
            case "client_credentials" ->
                    clientCredentialsGrant(clientIdParam, clientSecretParam, authorizationHeader);
            default -> throw OAuth2TokenException.unsupportedGrantType(
                    "Unsupported grant_type: '" + grantType + "'. Use 'password' or 'client_credentials'.");
        };
    }

    // ------------------------------------------------------------------ grants

    private TokenResponse passwordGrant(String username, String password) {
        if (username == null || password == null) {
            throw OAuth2TokenException.invalidRequest("'username' and 'password' are required.");
        }

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
        } catch (AuthenticationException ex) {
            throw OAuth2TokenException.invalidGrant("Bad credentials for user '" + username + "'.");
        }

        List<String> roles = rolesFromAuthorities(authentication.getAuthorities());
        Set<String> scopes = defaultUserScopes(roles);

        JwtTokenService.IssuedToken token = tokenService.issue(username, roles, scopes);
        return TokenResponse.bearer(token.value(), token.expiresInSeconds(), token.scope(), roles);
    }

    private TokenResponse clientCredentialsGrant(String clientIdParam,
                                                 String clientSecretParam,
                                                 String authorizationHeader) {
        String[] credentials = resolveClientCredentials(clientIdParam, clientSecretParam, authorizationHeader);
        String clientId = credentials[0];
        String clientSecret = credentials[1];

        OAuthClient client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> OAuth2TokenException.invalidClient("Unknown client '" + clientId + "'."));

        if (!passwordEncoder.matches(clientSecret, client.getClientSecret())) {
            throw OAuth2TokenException.invalidClient("Invalid client secret.");
        }

        List<String> roles = client.getRoles().stream().map(Role::name).sorted().toList();
        Set<String> scopes = new TreeSet<>(client.getScopes());

        JwtTokenService.IssuedToken token = tokenService.issue(clientId, roles, scopes);
        return TokenResponse.bearer(token.value(), token.expiresInSeconds(), token.scope(), roles);
    }

    // ------------------------------------------------------------------ helpers

    private String[] resolveClientCredentials(String clientIdParam,
                                              String clientSecretParam,
                                              String authorizationHeader) {
        // Prefer HTTP Basic (RFC 6749 recommends it) but fall back to form params.
        if (authorizationHeader != null && authorizationHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            String base64 = authorizationHeader.substring(6).trim();
            String decoded = new String(Base64.getDecoder().decode(base64), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) {
                throw OAuth2TokenException.invalidClient("Malformed Basic authorization header.");
            }
            return new String[]{decoded.substring(0, colon), decoded.substring(colon + 1)};
        }
        if (clientIdParam != null && clientSecretParam != null) {
            return new String[]{clientIdParam, clientSecretParam};
        }
        throw OAuth2TokenException.invalidClient(
                "Client authentication required (HTTP Basic or client_id/client_secret).");
    }

    private static List<String> rolesFromAuthorities(java.util.Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring("ROLE_".length()))
                .sorted()
                .collect(Collectors.toList());
    }

    private static Set<String> defaultUserScopes(List<String> roles) {
        // Give every authenticated user a baseline read scope; managers/admins get more.
        Set<String> scopes = new TreeSet<>(Set.of("profile", "api.read"));
        if (roles.contains("MANAGER") || roles.contains("ADMIN")) {
            scopes.add("api.write");
        }
        return scopes;
    }

    // ------------------------------------------------------------------ errors

    @ExceptionHandler(OAuth2TokenException.class)
    public ResponseEntity<Map<String, String>> handleOAuthError(OAuth2TokenException ex) {
        Map<String, String> body = Map.of(
                "error", ex.getError(),
                "error_description", ex.getMessage() == null ? "" : ex.getMessage());
        return ResponseEntity.status(ex.getStatus()).body(body);
    }

    @ExceptionHandler(org.springframework.web.bind.MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, String>> handleMissingParam(
            org.springframework.web.bind.MissingServletRequestParameterException ex) {
        Map<String, String> body = Map.of(
                "error", "invalid_request",
                "error_description", "Missing required parameter: " + ex.getParameterName());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }
}
