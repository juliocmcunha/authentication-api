package org.juliocmcnha.auth2r.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Metadata for the interactive API documentation served at {@code /swagger-ui.html}.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI apiInfo() {
        return new OpenAPI().info(new Info()
                .title("OAuth2 + RBAC Demo API")
                .version("1.0.0")
                .description("A self-contained OAuth2 authorization/resource server with "
                        + "role-based access control. Obtain a token from POST /oauth2/token, "
                        + "then call the /api/** endpoints with an Authorization: Bearer header.")
                .license(new License().name("MIT")));
    }
}
