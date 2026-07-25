package org.juliocmcnha.auth2r.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Turns the custom claims in an incoming JWT into Spring Security authorities.
 *
 * <ul>
 *   <li>{@code roles: ["USER","ADMIN"]} &rarr; {@code ROLE_USER}, {@code ROLE_ADMIN}</li>
 *   <li>{@code scope: "api.read api.write"} &rarr; {@code SCOPE_api.read}, {@code SCOPE_api.write}</li>
 * </ul>
 *
 * This lets {@code hasRole('ADMIN')} and {@code hasAuthority('SCOPE_api.read')}
 * both work against the same token.
 */
public class JwtAuthoritiesConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles != null) {
            for (String role : roles) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
        }

        String scope = jwt.getClaimAsString("scope");
        if (scope != null && !scope.isBlank()) {
            for (String s : scope.trim().split("\\s+")) {
                authorities.add(new SimpleGrantedAuthority("SCOPE_" + s));
            }
        }

        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }
}
