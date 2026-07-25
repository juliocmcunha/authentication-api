package org.juliocmcnha.auth2r.security;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;

/**
 * Builds signed JWT access tokens.
 *
 * <p>Tokens carry:
 * <ul>
 *   <li>{@code sub} &mdash; the subject (username or client id)</li>
 *   <li>{@code roles} &mdash; bare role names, e.g. {@code ["USER","ADMIN"]}</li>
 *   <li>{@code scope} &mdash; a space-delimited scope string, OAuth2 style</li>
 * </ul>
 * The resource server maps {@code roles} to {@code ROLE_*} authorities and
 * {@code scope} to {@code SCOPE_*} authorities (see {@link JwtAuthoritiesConverter}).
 */
@Service
public class JwtTokenService {

    public static final String ISSUER = "https://oauth2-rbac-demo.local";
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(15);

    private final JwtEncoder jwtEncoder;
    private final RSAKey rsaKey;

    public JwtTokenService(JwtEncoder jwtEncoder, RSAKey rsaKey) {
        this.jwtEncoder = jwtEncoder;
        this.rsaKey = rsaKey;
    }

    /** Convenience overload using the default 15-minute lifetime. */
    public IssuedToken issue(String subject, Collection<String> roles, Collection<String> scopes) {
        return issue(subject, roles, scopes, DEFAULT_TTL);
    }

    public IssuedToken issue(String subject,
                             Collection<String> roles,
                             Collection<String> scopes,
                             Duration ttl) {
        Instant now = Instant.now();
        Instant expiry = now.plus(ttl);
        String scopeString = String.join(" ", scopes);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(ISSUER)
                .issuedAt(now)
                .expiresAt(expiry)
                .subject(subject)
                .claim("roles", List.copyOf(roles))
                .claim("scope", scopeString)
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(rsaKey.getKeyID())
                .build();

        String tokenValue = jwtEncoder
                .encode(JwtEncoderParameters.from(header, claims))
                .getTokenValue();

        return new IssuedToken(tokenValue, ttl.toSeconds(), scopeString);
    }

    /** Simple carrier for an issued token and the metadata the token endpoint returns. */
    public record IssuedToken(String value, long expiresInSeconds, String scope) {
    }
}
