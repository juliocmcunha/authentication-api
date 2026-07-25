package org.juliocmcnha.auth2r;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Exercises the full path: request a real signed token from {@code /oauth2/token},
 * then use it as a bearer token against the protected API. This verifies that the
 * JWT is issued, signed, decoded, and its roles enforced correctly.
 */
@SpringBootTest
@AutoConfigureMockMvc
class TokenEndpointTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void adminUserGetsTokenAndReachesAdminEndpoint() throws Exception {
        String token = passwordToken("carol", "carol123");

        mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.principal").value("carol"));
    }

    @Test
    void regularUserIsForbiddenFromAdminEndpointWithRealToken() throws Exception {
        String token = passwordToken("alice", "alice123");

        mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());

        // ...but can read their own profile
        mockMvc.perform(get("/api/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void badCredentialsAreRejectedWithInvalidGrant() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", "alice")
                        .param("password", "wrong-password"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void unsupportedGrantTypeIsRejected() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    @Test
    void clientCredentialsGrantHasManagerButNotAdminRights() throws Exception {
        String basic = Base64.getEncoder()
                .encodeToString("demo-console:console-secret".getBytes(StandardCharsets.UTF_8));

        String response = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header("Authorization", "Basic " + basic)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String token = objectMapper.readTree(response).get("access_token").asText();

        mockMvc.perform(get("/api/reports").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/admin").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void invalidClientSecretIsRejected() throws Exception {
        String basic = Base64.getEncoder()
                .encodeToString("demo-console:wrong".getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header("Authorization", "Basic " + basic)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    // ------------------------------------------------------------------ helpers

    private String passwordToken(String username, String password) throws Exception {
        String response = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", username)
                        .param("password", password))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        JsonNode json = objectMapper.readTree(response);
        return json.get("access_token").asText();
    }
}
