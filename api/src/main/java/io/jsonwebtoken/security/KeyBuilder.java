package io.jsonwebtoken.security;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * A {@code KeyBuilder} produces new {@link Key}s suitable for use with an associated cryptographic algorithm.
 * A new {@link Key} is created each time the builder's {@link #build()} method is called.
 *
 * <p>{@code KeyBuilder}s are provided by components that implement the {@link KeyBuilderSupplier} interface,
 * ensuring the resulting {@link SecretKey}s are compatible with their associated cryptographic algorithm.</p>
 *
 * @param <K> the type of key to build
 * @param <B> the type of the builder, for subtype method chaining
 * @see KeyBuilderSupplier
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyBuilder<K extends Key, B extends KeyBuilder<K, B>> extends SecurityBuilder<K, B> {
}
