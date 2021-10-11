package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * A {@code KeyAlgorithm} produces the {@link SecretKey} used to encrypt or decrypt a JWE. The {@code KeyAlgorithm}
 * used for a particular JWE is {@link #getId() identified} in the JWE's
 * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">{@code alg} header</a>.
 * <p/>
 * <p>The {@code KeyAlgorithm} interface is JJWT's idiomatic approach to the JWE specification's
 * <code><a href="https://tools.ietf.org/html/rfc7516#section-2">{@code Key Management Mode}</a></code> concept.</p>
 *
 * @since JJWT_RELEASE_VERSION
 * @see <a href="https://tools.ietf.org/html/rfc7516#section-2">RFC 7561, Section 2: JWE Key (Management) Algorithms</a>
 */
public interface KeyAlgorithm<E extends Key, D extends Key> extends Identifiable {

    KeyResult getEncryptionKey(KeyRequest<SecretKey, E> request) throws SecurityException;

    SecretKey getDecryptionKey(KeyRequest<byte[], D> request) throws SecurityException;
}
