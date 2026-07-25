# OAuth2 + Role-Based Access Control — Demo

A self-contained **Java 17+/Spring Boot 3** application that implements **OAuth2 token
issuance and validation** together with **role-based access control (RBAC)**. It runs
with a single command, seeds its own users, and prints a **live console walkthrough**
that shows tokens being issued and access being allowed or denied by role.

Built with **Gradle (Groovy DSL)**. No external services, databases, or accounts required.

> Portfolio note: the goal of this project is to demonstrate a clear understanding of
> how OAuth2 bearer tokens, JWTs, and Spring Security authorities fit together — not to
> hide it behind a black box. Every moving part (signing keys, the token endpoint, the
> resource server, the authority mapping) is small and readable.

---

## What it demonstrates

- **OAuth2 token endpoint** (`POST /oauth2/token`) supporting the `password` and
  `client_credentials` grants and returning **RS256-signed JWT** access tokens.
- **OAuth2 Resource Server**: `/api/**` endpoints protected by Spring Security, validating
  the JWT signature against a published **JWKS** endpoint.
- **Role-based access control**: `USER`, `MANAGER`, and `ADMIN` roles enforced both at the
  URL level (`authorizeHttpRequests`) and at the method level (`@PreAuthorize`).
- **Scopes** carried alongside roles in the same token.
- **BCrypt** password/secret hashing, users & clients persisted in an in-memory **H2** database.
- A **console demo** that logs in three users of increasing privilege plus a machine client,
  decodes each JWT, and calls every endpoint so you can see `ALLOW` / `DENY` in real time.
- **Tests** (JUnit 5 + `spring-security-test`) covering the authorization rules and the
  full token round-trip.
- Extras that make a repo pleasant to review: **Swagger UI**, **Actuator health**,
  **Dockerfile**, and a **GitHub Actions** CI workflow.

---

## Architecture

```
                       ┌────────────────────────────────────────────┐
                       │            Spring Boot application           │
                       │                                              │
  POST /oauth2/token   │   ┌──────────────────┐   issues (RS256)      │
  (password /          │   │  TokenController │──────────────┐        │
   client_credentials) ├──▶│  + JwtTokenService│              ▼        │
                       │   └──────────────────┘        signed JWT      │
                       │        ▲    ▲                   (access_token) │
             BCrypt    │        │    │                        │        │
        AuthenticationMgr ──────┘    └── OAuthClientRepository │        │
             + H2 users                                        │        │
                       │                                       ▼        │
  GET /api/**          │   ┌──────────────────────────────────────┐    │
  Authorization:       ├──▶│  Resource Server filter chain          │   │
  Bearer <jwt>         │   │  • verifies signature via JwtDecoder    │   │
                       │   │  • maps roles→ROLE_*, scope→SCOPE_*     │   │
                       │   │  • enforces hasRole / @PreAuthorize     │   │
                       │   └──────────────────────────────────────┘    │
                       │                                              │
  GET /oauth2/jwks     │   public key so anyone can verify tokens     │
                       └────────────────────────────────────────────┘
```

**Roles → authorities.** A token carries roles as bare names (`"roles":["USER","ADMIN"]`).
The resource server maps each to a `ROLE_*` authority, so `hasRole('ADMIN')` and
`@PreAuthorize("hasRole('ADMIN')")` work. Scopes map to `SCOPE_*` authorities.

---

## Tech stack

| Concern            | Choice                                             |
|--------------------|----------------------------------------------------|
| Language / runtime | Java 21 (toolchain), Java 17+ compatible source    |
| Framework          | Spring Boot 3.3, Spring Security 6                  |
| Tokens             | JWT (RS256) via Spring Security OAuth2 + Nimbus JOSE|
| Persistence        | Spring Data JPA + H2 (in-memory)                    |
| Build              | Gradle 8 (Groovy DSL)                               |
| Docs               | springdoc-openapi (Swagger UI)                      |
| Tests              | JUnit 5, spring-security-test                       |

---

## Quick start

Requires **JDK 21**. You can build in either of two ways.

**Option A — with the Gradle wrapper** (recommended). If `gradlew` is not present yet,
generate it once with an installed Gradle, then use the wrapper thereafter:

```bash
gradle wrapper            # creates ./gradlew and the wrapper jar (one-time)
./gradlew bootRun
```

**Option B — with a locally installed Gradle 8.5+:**

```bash
gradle bootRun
```

The app starts on **http://localhost:8080** and the console demo runs automatically a
moment after startup.

Skip the console demo:

```bash
./gradlew bootRun --args='--demo.run-console=false'
```

---

## Demo identities

Seeded automatically at startup.

**Users** (use the `password` grant):

| Username | Password   | Roles                    |
|----------|------------|--------------------------|
| `alice`  | `alice123` | USER                     |
| `bob`    | `bob123`   | USER, MANAGER            |
| `carol`  | `carol123` | USER, MANAGER, ADMIN     |

**Client** (uses the `client_credentials` grant):

| Client ID      | Secret           | Roles   | Scopes              |
|----------------|------------------|---------|---------------------|
| `demo-console` | `console-secret` | MANAGER | `api.read api.write`|

---

## Endpoints

| Method & path        | Access rule                    |
|----------------------|--------------------------------|
| `GET /api/public`    | Everyone (no token)            |
| `GET /api/profile`   | Any authenticated caller       |
| `GET /api/reports`   | `MANAGER` or `ADMIN`           |
| `GET /api/admin`     | `ADMIN` only                   |
| `POST /oauth2/token` | Public (does its own auth)     |
| `GET /oauth2/jwks`   | Public (public keys only)      |
| `GET /swagger-ui.html` | Public — interactive docs    |
| `GET /h2-console`    | Public (demo only) — JDBC URL `jdbc:h2:mem:oauthdemo` |

---

## Try it with curl

Get a token for the admin user and call the admin endpoint:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/oauth2/token \
  -d grant_type=password -d username=carol -d password=carol123 \
  | sed -E 's/.*"access_token":"([^"]+)".*/\1/')

curl -s http://localhost:8080/api/admin -H "Authorization: Bearer $TOKEN"
```

The same token against `/api/admin` for `alice` returns **403 Forbidden** — RBAC in action.

Machine-to-machine (client credentials, HTTP Basic):

```bash
curl -s -X POST http://localhost:8080/oauth2/token \
  -u demo-console:console-secret \
  -d grant_type=client_credentials
```

---

## Sample console output

```
══════════════════════════════════════════════════════════════════
  OAuth2 + Role-Based Access Control — live console demo
══════════════════════════════════════════════════════════════════
  Server: http://localhost:8080   |   Token endpoint: POST /oauth2/token
  Legend: ALLOW = 2xx    DENY = 401/403

── USER LOGIN — alice  (a regular USER) ─────────────────────────
  ✔ token issued
    roles : [USER]
    scope : api.read profile
    decoded JWT claims:
      { "iss": "https://oauth2-rbac-demo.local",
        "sub": "alice", "roles": ["USER"], "scope": "api.read profile", ... }
  Calling protected endpoints:
    ALLOW  /api/public     HTTP 200
    ALLOW  /api/profile    HTTP 200
    DENY   /api/reports    HTTP 403
    DENY   /api/admin      HTTP 403

── USER LOGIN — bob  (a MANAGER) ────────────────────────────────
  ✔ token issued
    roles : [MANAGER, USER]
    ...
    ALLOW  /api/reports    HTTP 200
    DENY   /api/admin      HTTP 403

── USER LOGIN — carol  (an ADMIN) ───────────────────────────────
    ALLOW  /api/reports    HTTP 200
    ALLOW  /api/admin      HTTP 200

── CLIENT CREDENTIALS — demo-console  (machine-to-machine) ──────
    ALLOW  /api/reports    HTTP 200
    DENY   /api/admin      HTTP 403

── NO TOKEN — anonymous caller ──────────────────────────────────
    ALLOW  /api/public     HTTP 200
    DENY   /api/profile    HTTP 401
══════════════════════════════════════════════════════════════════
  Demo complete.
══════════════════════════════════════════════════════════════════
```

---

## Testing

```bash
./gradlew test
```

- `ApiSecurityTest` — checks each URL/method rule using a JWT with chosen authorities.
- `TokenEndpointTest` — issues real signed tokens and verifies the full validate-and-enforce
  path, including bad credentials, an unsupported grant, and client-credentials role limits.

---

## Project structure

```
src/main/java/com/portfolio/oauth2rbac
├── OAuth2RbacApplication.java      # entry point
├── config/
│   ├── SecurityConfig.java         # two filter chains: public + resource server
│   ├── JwtConfig.java              # RSA key, JwtEncoder, JwtDecoder, JWKS source
│   ├── DataSeeder.java             # seeds demo users & client
│   └── OpenApiConfig.java          # Swagger metadata
├── domain/                         # AppUser, OAuthClient, Role
├── repository/                     # Spring Data JPA repositories
├── security/
│   ├── AppUserDetailsService.java  # loads users for the password grant
│   ├── JwtTokenService.java        # builds & signs JWTs
│   └── JwtAuthoritiesConverter.java# roles/scope claims → authorities
├── oauth/
│   ├── TokenController.java        # /oauth2/token
│   ├── JwksController.java         # /oauth2/jwks
│   └── TokenResponse / OAuth2TokenException
├── api/ApiControllers.java         # public / profile / reports / admin
└── demo/ConsoleDemoRunner.java     # the live walkthrough
```

---

## Design notes & production considerations

This is a **learning/portfolio** project. In a production system you would additionally:

- **Signing keys**: load a stable RSA key from a secret store / keystore instead of
  generating an ephemeral pair on each boot, and support key rotation via the JWKS endpoint.
- **Grant types**: prefer **Authorization Code + PKCE** for user login. The `password`
  grant is used here purely because it makes a console-only demonstration of the
  user → token → role-protected-API flow straightforward; it is discouraged in OAuth 2.1.
  For a full standards-compliant server, swap this layer for
  [**Spring Authorization Server**](https://spring.io/projects/spring-authorization-server).
- **Refresh tokens & revocation**: add refresh tokens, short access-token lifetimes, and a
  revocation/introspection endpoint.
- **Storage**: replace H2 with a real database (PostgreSQL) and add Flyway migrations.
- **Hardening**: disable the H2 console, add rate limiting on the token endpoint, audit
  logging, and CORS configuration for browser clients.

## Possible extensions

- Social login (Google / GitHub) via `spring-boot-starter-oauth2-client`.
- Fine-grained permissions (authorities beyond roles) and a permission-per-endpoint matrix.
- A small front-end (React) that performs the Authorization Code + PKCE flow in a browser.

---

## License

MIT — see [LICENSE](LICENSE).
