package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * A {@link KeyAlgorithm} that uses symmetric {@link SecretKey}s to obtain AEAD encryption and decryption keys.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface SecretKeyAlgorithm extends KeyAlgorithm<SecretKey, SecretKey>, KeyBuilderSupplier<SecretKey, SecretKeyBuilder>, KeyLengthSupplier {
}
