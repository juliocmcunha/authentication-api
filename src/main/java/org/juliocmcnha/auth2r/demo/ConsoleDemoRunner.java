package org.juliocmcnha.auth2r.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs after the application (and its embedded web server) has started and drives a
 * scripted walk-through of the whole system, printing a readable report to the console.
 *
 * <p>For each demo identity it:
 * <ol>
 *   <li>requests an access token from {@code POST /oauth2/token},</li>
 *   <li>decodes and prints the JWT payload (claims),</li>
 *   <li>calls every {@code /api/**} endpoint and prints the resulting HTTP status,</li>
 * </ol>
 * so you can literally see role-based access control allowing and denying requests.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class ConsoleDemoRunner implements ApplicationRunner {

    // --- ANSI styling -------------------------------------------------------
    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String DIM = "\u001B[2m";
    private static final String CYAN = "\u001B[36m";
    private static final String GREEN = "\u001B[32m";
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String BLUE = "\u001B[34m";

    private final ObjectMapper objectMapper;
    private final boolean enabled;
    private final boolean color;
    private final String baseUrl;

    public ConsoleDemoRunner(ObjectMapper objectMapper,
                             @Value("${server.port:8080}") int port,
                             @Value("${demo.run-console:true}") boolean enabled,
                             @Value("${demo.color:true}") boolean color) {
        this.objectMapper = objectMapper;
        this.enabled = enabled;
        this.color = color;
        this.baseUrl = "http://localhost:" + port;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!enabled) {
            return;
        }
        RestClient http = RestClient.create();

        printBanner();

        // 1) Password grant for three users with increasing privilege.
        demoUser(http, "alice", "alice123", "a regular USER");
        demoUser(http, "bob", "bob123", "a MANAGER");
        demoUser(http, "carol", "carol123", "an ADMIN");

        // 2) Machine-to-machine client_credentials grant.
        demoClient(http, "demo-console", "console-secret");

        // 3) An unauthenticated call, to show the public endpoint and a 401.
        demoAnonymous(http);

        printFooter();
    }

    // ------------------------------------------------------------------ flows

    private void demoUser(RestClient http, String username, String password, String describe) {
        section("USER LOGIN — " + username + "  (" + describe + ")");

        TokenResult token = requestPasswordToken(http, username, password);
        if (token == null) {
            return;
        }
        line(GREEN, "  ✔ token issued");
        line(DIM, "    roles : " + token.roles());
        line(DIM, "    scope : " + token.scope());
        printClaims(token.accessToken());

        callAllEndpoints(http, token.accessToken());
    }

    private void demoClient(RestClient http, String clientId, String clientSecret) {
        section("CLIENT CREDENTIALS — " + clientId + "  (machine-to-machine)");

        TokenResult token = requestClientToken(http, clientId, clientSecret);
        if (token == null) {
            return;
        }
        line(GREEN, "  ✔ token issued");
        line(DIM, "    roles : " + token.roles());
        line(DIM, "    scope : " + token.scope());
        printClaims(token.accessToken());

        callAllEndpoints(http, token.accessToken());
    }

    private void demoAnonymous(RestClient http) {
        section("NO TOKEN — anonymous caller");
        callEndpoint(http, "/api/public", null);
        callEndpoint(http, "/api/profile", null);
    }

    // ------------------------------------------------------------------ token calls

    private TokenResult requestPasswordToken(RestClient http, String username, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", password);
        return postToken(http, form, null);
    }

    private TokenResult requestClientToken(RestClient http, String clientId, String clientSecret) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        String basic = Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        return postToken(http, form, "Basic " + basic);
    }

    @SuppressWarnings("unchecked")
    private TokenResult postToken(RestClient http, MultiValueMap<String, String> form, String authHeader) {
        try {
            RestClient.RequestBodySpec spec = http.post()
                    .uri(baseUrl + "/oauth2/token")
                    .header("Content-Type", "application/x-www-form-urlencoded");
            if (authHeader != null) {
                spec = spec.header("Authorization", authHeader);
            }
            ResponseEntity<Map> response = spec.body(form)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> { /* swallow, inspect below */ })
                    .toEntity(Map.class);

            Map<String, Object> b = response.getBody();
            if (response.getStatusCode().isError() || b == null || !b.containsKey("access_token")) {
                line(RED, "  \u2717 token request failed: " + b);
                return null;
            }
            return new TokenResult(
                    (String) b.get("access_token"),
                    String.valueOf(b.getOrDefault("scope", "")),
                    (List<Object>) b.getOrDefault("roles", List.of()));
        } catch (Exception ex) {
            line(RED, "  ✗ token request error: " + ex.getMessage());
            return null;
        }
    }

    // ------------------------------------------------------------------ api calls

    private void callAllEndpoints(RestClient http, String accessToken) {
        line(BOLD, "  Calling protected endpoints:");
        callEndpoint(http, "/api/public", accessToken);
        callEndpoint(http, "/api/profile", accessToken);
        callEndpoint(http, "/api/reports", accessToken);
        callEndpoint(http, "/api/admin", accessToken);
    }

    private void callEndpoint(RestClient http, String path, String accessToken) {
        try {
            RestClient.RequestHeadersSpec<?> spec = http.get().uri(baseUrl + path);
            if (accessToken != null) {
                spec = spec.header("Authorization", "Bearer " + accessToken);
            }
            ResponseEntity<String> response = spec
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> { /* swallow */ })
                    .toEntity(String.class);

            int code = response.getStatusCode().value();
            boolean ok = response.getStatusCode().is2xxSuccessful();
            String verdict = ok ? GREEN + "ALLOW " : RED + "DENY  ";
            String label = String.format("%-14s", path);
            System.out.println("    " + paint(verdict) + RESET + " " + label
                    + paint(DIM) + " HTTP " + code + RESET);
        } catch (Exception ex) {
            System.out.println("    " + paint(RED) + "ERROR " + RESET + path + " -> " + ex.getMessage());
        }
    }

    // ------------------------------------------------------------------ jwt claims

    private void printClaims(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                return;
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            Map<?, ?> claims = objectMapper.readValue(payload, Map.class);
            // Order the interesting claims first for readability.
            Map<String, Object> ordered = new LinkedHashMap<>();
            for (String key : List.of("iss", "sub", "roles", "scope", "iat", "exp")) {
                if (claims.containsKey(key)) {
                    ordered.put(key, claims.get(key));
                }
            }
            String pretty = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(ordered);
            line(BLUE, "    decoded JWT claims:");
            for (String l : pretty.split("\n")) {
                line(DIM, "      " + l);
            }
        } catch (Exception ex) {
            line(RED, "    (could not decode JWT: " + ex.getMessage() + ")");
        }
    }

    // ------------------------------------------------------------------ printing

    private void printBanner() {
        System.out.println();
        line(CYAN + BOLD, "══════════════════════════════════════════════════════════════════");
        line(CYAN + BOLD, "  OAuth2 + Role-Based Access Control — live console demo");
        line(CYAN + BOLD, "══════════════════════════════════════════════════════════════════");
        line(DIM, "  Server: " + baseUrl + "   |   Token endpoint: POST /oauth2/token");
        line(DIM, "  Legend: " + paint(GREEN) + "ALLOW" + RESET + paint(DIM)
                + " = 2xx    " + RESET + paint(RED) + "DENY" + RESET + paint(DIM)
                + " = 401/403" + RESET);
    }

    private void printFooter() {
        System.out.println();
        line(CYAN + BOLD, "══════════════════════════════════════════════════════════════════");
        line(GREEN + BOLD, "  Demo complete.");
        line(DIM, "  Try it yourself:");
        line(DIM, "    curl -s -XPOST " + baseUrl + "/oauth2/token \\");
        line(DIM, "      -d grant_type=password -d username=carol -d password=carol123");
        line(DIM, "  Swagger UI: " + baseUrl + "/swagger-ui.html");
        line(DIM, "  JWKS:       " + baseUrl + "/oauth2/jwks");
        line(CYAN + BOLD, "══════════════════════════════════════════════════════════════════");
        System.out.println();
    }

    private void section(String title) {
        System.out.println();
        line(YELLOW + BOLD, "── " + title + " " + "─".repeat(Math.max(0, 60 - title.length())));
    }

    private void line(String style, String text) {
        System.out.println(paint(style) + text + (color ? RESET : ""));
    }

    private String paint(String style) {
        return color ? style : "";
    }

    /** Minimal carrier for a token plus the metadata we display. */
    private record TokenResult(String accessToken, String scope, List<Object> roles) {
    }
}
