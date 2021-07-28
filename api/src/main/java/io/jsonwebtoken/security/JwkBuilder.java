package io.jsonwebtoken.security;

import java.security.Key;
import java.security.Provider;
import java.util.Map;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkBuilder<K extends Key, J extends Jwk<?, K>, T extends JwkBuilder<K, J, T>> {

    T put(String name, Object value);

    T putAll(Map<String,?> values);

    T setAlgorithm(String alg);

    T setId(String id);

    T setOperations(Set<String> ops);

    /**
     * Sets the JCA Provider to use during key operations, or {@code null} if the
     * JCA subsystem preferred provider should be used.
     *
     * @param provider the JCA Provider to use during key operations, or {@code null} if the
     *                 JCA subsystem preferred provider should be used.
     * @return the builder for method chaining.
     */
    T setProvider(Provider provider);

    J build();
}
