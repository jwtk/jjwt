package io.jsonwebtoken.security;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * A <code><a href="https://tools.ietf.org/html/rfc7516#section-2">Key Management Algorithm</a></code> is an algorithm that
 * produces a {@link SecretKey} used to encrypt or decrypt a JWE.  The Key Management Algorithm used for a particular
 * JWE is {@link #getId() identified} in the
 * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">JWE's {@code alg} header</a>.
 * <h4>Key Management Mode</h4>
 * The JWE specification indicates that all {@code Key Management Algorithm}s utilize what is called a
 * {@code Key Management Mode} to indicate if the encryption key will be supplied to a JWE recipient within the
 * JWE as an encrypted value. <b>This interface does not indicate which {@code Key Management Mode} is used:</b>
 * the {@link #getEncryptionKey(KeyRequest) key result} may contain either an empty or populated encrypted key via
 * {@link KeyResult#getPayload() result.getPayload()}.
 * <p>Therefore, <b>algorithms that produce encrypted keys <em>MUST</em> implement the
 * {@link EncryptedKeyAlgorithm} interface instead of this one.</b></p>
 *
 * @since JJWT_RELEASE_VERSION
 * @see EncryptedKeyAlgorithm
 */
public interface KeyAlgorithm<E extends Key, D extends Key> extends Identifiable {

    KeyResult getEncryptionKey(KeyRequest<SecretKey, E> request) throws SecurityException;

    SecretKey getDecryptionKey(KeyRequest<byte[], D> request) throws SecurityException;
}
