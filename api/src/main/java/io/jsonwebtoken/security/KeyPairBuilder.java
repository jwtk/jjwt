package io.jsonwebtoken.security;

import java.security.KeyPair;

/**
 * A {@code KeyPairBuilder} produces new {@link KeyPair}s suitable for use with an associated cryptographic algorithm.
 * A new {@link KeyPair} is created each time the builder's {@link #build()} method is called.
 *
 * <p>{@code KeyPairBuilder}s are provided by components that implement the {@link KeyPairBuilderSupplier} interface,
 * ensuring the resulting {@link KeyPair}s are compatible with their associated cryptographic algorithm.</p>
 *
 * @see KeyPairBuilderSupplier
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyPairBuilder extends SecurityBuilder<KeyPair, KeyPairBuilder> {
}
