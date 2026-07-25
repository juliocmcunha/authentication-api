package org.juliocmcnha.auth2r.oauth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Standard-shaped OAuth2 access-token response body.
 * The {@code roles} field is a convenience extension so the demo console can display
 * them without decoding the token.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn,
        @JsonProperty("scope") String scope,
        @JsonProperty("roles") List<String> roles) {

    public static TokenResponse bearer(String accessToken, long expiresIn, String scope, List<String> roles) {
        return new TokenResponse(accessToken, "Bearer", expiresIn, scope, roles);
    }
}
