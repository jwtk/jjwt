package io.jsonwebtoken.security;

import java.security.Key;
import java.util.Map;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface Jwk<V, K extends Key> extends Identifiable, Map<String,V> {

    String getType();

    Set<String> getOperations();

    String getAlgorithm();

    String getId();
    
    K toKey();
}
