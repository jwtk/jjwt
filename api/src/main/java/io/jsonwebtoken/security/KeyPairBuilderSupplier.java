package io.jsonwebtoken.security;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface implemented by components that support building/creating new {@link KeyPair}s suitable for use with their
 * associated cryptographic algorithm implementation.
 *
 * @param <A> type of public key found in newly-created {@code KeyPair}s
 * @param <B> type of private key found in newly-created {@code KeyPair}s
 * @see #keyPairBuilder()
 * @see KeyPairBuilder
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyPairBuilderSupplier<A extends PublicKey, B extends PrivateKey> {

    /**
     * Returns a new {@link KeyPairBuilder} that will create new secure-random {@link KeyPair}s with a length and
     * parameters sufficient for use with the component's associated cryptographic algorithm.
     *
     * @return a new {@link KeyPairBuilder} that will create new secure-random {@link KeyPair}s with a length and
     * parameters sufficient for use with the component's associated cryptographic algorithm.
     */
    KeyPairBuilder<A, B> keyPairBuilder();
}
