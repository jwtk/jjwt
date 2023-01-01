package io.jsonwebtoken.security;

import java.net.URI;

/**
 * A canonical cryptographic digest of a JWK as defined by the
 * <a href="https://www.rfc-editor.org/rfc/rfc7638">JSON Web Key (JWK) Thumbprint</a> specification.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkThumbprint {

    /**
     * Returns the {@link HashAlgorithm} used to compute the thumbprint.
     *
     * @return the {@link HashAlgorithm} used to compute the thumbprint.
     */
    HashAlgorithm getHashAlgorithm();

    /**
     * Returns the actual thumbprint (aka digest) byte array value.
     *
     * @return the actual thumbprint (aka digest) byte array value.
     */
    byte[] toByteArray();

    /**
     * Returns the canonical URI representation of this thumbprint as defined by the
     * <a href="https://www.rfc-editor.org/rfc/rfc9278.html">JWK Thumbprint URI</a> specification.
     *
     * @return a canonical JWK Thumbprint URI
     */
    URI toURI();

    /**
     * Returns the {@link #toByteArray()} as a Base64URL-encoded string.
     */
    String toString();
}
