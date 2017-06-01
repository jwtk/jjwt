package io.jsonwebtoken;

import java.util.List;
import java.util.Map;

/**
 * A {@code JwkSet} represents a set of {@link Jwk}s.
 *
 * @param <T> JwkSet type
 * @since 0.7
 */
public interface JwkSet<T extends JwkSet<T>> extends Map<String, Object> {

    /**
     * JWK Set <a href="https://tools.ietf.org/html/rfc7517#section-5.1">Keys Parameter</a> name: the string literal <b><code>keys</code></b>
     */
    public static final String KEYS = "keys";

    /**
     * Returns a list of {@code Jwk}s.  By default, the order of the JWK values within the List does not imply an
     * order of preference among them, although applications can choose to assign a meaning to the order
     * for their purposes, if desired.
     *
     * @return a list of {@code Jwk}s
     */
    List<Jwk> getKeys();

    /**
     * Sets a list of {@code Jwk}s.  By default, the order of the JWK values within the List does not imply an
     * order of preference among them, although applications can choose to assign a meaning to the order
     * for their purposes, if desired.
     *
     * @param keys a list of {@code Jwk}s
     */
    T setKeys(List<Jwk> keys);
}
