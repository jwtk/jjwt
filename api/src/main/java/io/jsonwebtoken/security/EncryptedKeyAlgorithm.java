package io.jsonwebtoken.security;

import java.security.Key;

/**
 * A {@link KeyAlgorithm} that produces an encrypted key value. {@code EncryptedKeyAlgorithm}s will be supplied
 * a secure-randomly-generated Content Encryption Key in the request's {@link CryptoRequest#getPayload() getData()} method.
 *
 * <p>
 * <b>A {@code KeyAlgorithm} that does not produce an encrypted key value (or produces an empty key byte array) should
 * not implement this interface, and instead implement the {@code KeyAlgorithm} parent interface directly.</p>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface EncryptedKeyAlgorithm<E extends Key, D extends Key> extends KeyAlgorithm<E, D> {

}
