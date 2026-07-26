package org.juliocmcnha.auth2r.domain;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

import java.util.HashSet;
import java.util.Set;

/**
 * A registered OAuth2 client used for the {@code client_credentials} grant
 * (machine-to-machine access). The client secret is stored BCrypt-hashed.
 *
 * <p>Clients are granted roles and scopes just like users, so a "service identity"
 * can be given, for example, {@code MANAGER} rights without the full {@code ADMIN} set.
 */
@Entity
@Table(name = "oauth_clients")
public class OAuthClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, unique = true, length = 100)
    private String clientId;

    @Column(name = "client_secret", nullable = false)
    private String clientSecret;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_roles", joinColumns = @JoinColumn(name = "client_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 30)
    private Set<Role> roles = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_scopes", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope", nullable = false, length = 100)
    private Set<String> scopes = new HashSet<>();

    protected OAuthClient() {
    }

    public OAuthClient(String clientId, String clientSecret, Set<Role> roles, Set<String> scopes) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.roles = new HashSet<>(roles);
        this.scopes = new HashSet<>(scopes);
    }

    public Long getId() {
        return id;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
