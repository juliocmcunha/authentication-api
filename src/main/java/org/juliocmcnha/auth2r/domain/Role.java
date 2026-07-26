package org.juliocmcnha.auth2r.domain;

/**
 * Application roles. These map to Spring Security authorities with a {@code ROLE_}
 * prefix (e.g. {@code ADMIN} &rarr; {@code ROLE_ADMIN}) so that {@code hasRole('ADMIN')}
 * and {@code @PreAuthorize("hasRole('ADMIN')")} work as expected.
 */
public enum Role {
    USER,
    MANAGER,
    ADMIN;

    public String authority() {
        return "ROLE_" + name();
    }
}
