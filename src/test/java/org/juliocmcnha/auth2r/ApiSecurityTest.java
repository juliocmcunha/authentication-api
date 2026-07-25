package org.juliocmcnha.auth2r;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies the resource-server authorization rules independently of token minting,
 * by injecting a JWT with chosen authorities via spring-security-test.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ApiSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publicEndpointIsOpenWithoutToken() throws Exception {
        mockMvc.perform(get("/api/public"))
                .andExpect(status().isOk());
    }

    @Test
    void profileRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/profile"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void authenticatedUserCanReadProfile() throws Exception {
        mockMvc.perform(get("/api/profile").with(role("USER")))
                .andExpect(status().isOk());
    }

    @Test
    void regularUserCannotSeeReports() throws Exception {
        mockMvc.perform(get("/api/reports").with(role("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void managerCanSeeReports() throws Exception {
        mockMvc.perform(get("/api/reports").with(role("MANAGER")))
                .andExpect(status().isOk());
    }

    @Test
    void regularUserCannotSeeAdmin() throws Exception {
        mockMvc.perform(get("/api/admin").with(role("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void managerCannotSeeAdmin() throws Exception {
        mockMvc.perform(get("/api/admin").with(role("MANAGER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCanSeeAdmin() throws Exception {
        mockMvc.perform(get("/api/admin").with(role("ADMIN")))
                .andExpect(status().isOk());
    }

    /** Helper: a JWT post-processor carrying the given ROLE_ authority. */
    private static org.springframework.test.web.servlet.request.RequestPostProcessor role(String role) {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_" + role));
    }
}
