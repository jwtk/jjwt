package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;

import java.security.Key;
import java.util.Map;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface Jwk<K extends Key> extends Identifiable, Map<String,Object> {

    String getAlgorithm();

    Set<String> getOperations();

    String getType();

    K toKey();
}
