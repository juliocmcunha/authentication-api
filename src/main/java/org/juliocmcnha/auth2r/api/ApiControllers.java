package org.juliocmcnha.auth2r.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The protected (and one unprotected) API surface. Kept in a single file so the
 * whole access-control story is easy to read at a glance.
 *
 * <table border="1">
 *   <tr><th>Endpoint</th><th>Who can access</th></tr>
 *   <tr><td>GET /api/public</td><td>everyone (no token)</td></tr>
 *   <tr><td>GET /api/profile</td><td>any authenticated caller</td></tr>
 *   <tr><td>GET /api/reports</td><td>MANAGER or ADMIN</td></tr>
 *   <tr><td>GET /api/admin</td><td>ADMIN only</td></tr>
 * </table>
 */
public final class ApiControllers {

    private ApiControllers() {
    }

    private static Map<String, Object> body(String message, Authentication auth) {
        List<String> authorities = auth == null
                ? List.of()
                : auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList();
        return Map.of(
                "message", message,
                "principal", auth == null ? "anonymous" : auth.getName(),
                "authorities", authorities,
                "timestamp", Instant.now().toString());
    }

    @RestController
    @RequestMapping("/api/public")
    public static class PublicController {
        @GetMapping
        public Map<String, Object> publicEndpoint() {
            return Map.of(
                    "message", "This endpoint is open to everyone — no token required.",
                    "timestamp", Instant.now().toString());
        }
    }

    @RestController
    @RequestMapping("/api/profile")
    public static class ProfileController {
        @GetMapping
        public Map<String, Object> profile(Authentication authentication) {
            return body("Your token is valid. Here is what the server sees about you.", authentication);
        }
    }

    @RestController
    @RequestMapping("/api/reports")
    public static class ReportsController {
        @GetMapping
        @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
        public Map<String, Object> reports(Authentication authentication) {
            return body("Management reports — visible to MANAGER and ADMIN.", authentication);
        }
    }

    @RestController
    @RequestMapping("/api/admin")
    public static class AdminController {
        @GetMapping
        @PreAuthorize("hasRole('ADMIN')")
        public Map<String, Object> admin(Authentication authentication) {
            return body("Administration console — ADMIN only.", authentication);
        }
    }
}
