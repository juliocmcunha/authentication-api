package org.juliocmcnha.auth2r.oauth;

import org.springframework.http.HttpStatus;

/**
 * Represents an OAuth2 token-endpoint error (RFC 6749 section 5.2), e.g.
 * {@code invalid_grant}, {@code invalid_client}, {@code unsupported_grant_type}.
 */
public class OAuth2TokenException extends RuntimeException {

    private final String error;
    private final HttpStatus status;

    public OAuth2TokenException(String error, String description, HttpStatus status) {
        super(description);
        this.error = error;
        this.status = status;
    }

    public static OAuth2TokenException invalidRequest(String description) {
        return new OAuth2TokenException("invalid_request", description, HttpStatus.BAD_REQUEST);
    }

    public static OAuth2TokenException invalidClient(String description) {
        return new OAuth2TokenException("invalid_client", description, HttpStatus.UNAUTHORIZED);
    }

    public static OAuth2TokenException invalidGrant(String description) {
        return new OAuth2TokenException("invalid_grant", description, HttpStatus.BAD_REQUEST);
    }

    public static OAuth2TokenException unsupportedGrantType(String description) {
        return new OAuth2TokenException("unsupported_grant_type", description, HttpStatus.BAD_REQUEST);
    }

    public String getError() {
        return error;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
