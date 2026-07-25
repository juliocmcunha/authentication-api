package org.juliocmcnha.auth2r.repository;

import org.juliocmcnha.auth2r.domain.OAuthClient;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, Long> {

    Optional<OAuthClient> findByClientId(String clientId);
}
