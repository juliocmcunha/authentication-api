package org.juliocmcnha.auth2r.oauth;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Publishes the JSON Web Key Set (public keys only) so any resource server can
 * verify the signature of the tokens this application issues.
 */
@RestController
public class JwksController {

    private final JWKSet jwkSet;

    public JwksController(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @GetMapping("/oauth2/jwks")
    public Map<String, Object> keys() {
        // toJSONObject(true) => public parameters only (never leak the private key).
        return jwkSet.toJSONObject(true);
    }
}
