package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Identifiable;
import io.jsonwebtoken.security.Jwk;

import java.security.Key;

public interface FamilyJwkFactory<K extends Key, J extends Jwk<K>> extends JwkFactory<K, J>, Identifiable {

    boolean supports(JwkContext<?> context);
}
