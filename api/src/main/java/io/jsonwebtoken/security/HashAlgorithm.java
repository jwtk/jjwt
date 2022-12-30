package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;

/**
 * A {@link DigestAlgorithm} that computes and verifies digests without the use of a cryptographic key, such as for
 * thumbprints and <a href="https://en.wikipedia.org/wiki/Fingerprint_(computing)">digital fingerprint</a>s.
 *
 * <p><b>Standard Implementations</b></p>
 *
 * <p>Constant definitions and utility methods for all JWA (RFC 7518) standard
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic Algorithms for Digital Signatures and
 * MACs</a> are available via the {@link JwsAlgorithms} utility class.</p>
 *
 * <p><b>Standard Identifier</b></p>
 *
 * <p>{@code HashAlgorithm} extends {@link Identifiable}: the value returned from
 * {@link Identifiable#getId() getId()} in all JWT standard hash algorithms will return one of the
 * &quot;{@code Hash Name String}&quot; values defined in the IANA
 * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml">Named Information Hash
 * Algorithm Registry</a>. This is to ensure the correct algorithm ID is used within other JWT-standard identifiers,
 * such as within <a href="https://www.rfc-editor.org/rfc/rfc9278.html">JWK Thumbprint URI</a>s.</p>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface HashAlgorithm extends DigestAlgorithm<Request<byte[]>, VerifyDigestRequest> {
}
