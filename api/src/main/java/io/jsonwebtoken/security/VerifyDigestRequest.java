package io.jsonwebtoken.security;

/**
 * A request to verify a previously-computed cryptographic digest (available via {@link #getDigest()}) against the
 * digest to be computed for the specified {@link #getPayload() payload}.
 *
 * <p>Secure digest algorithms that use keys to perform
 * <a href="https://en.wikipedia.org/wiki/Digital_signature">digital signature</a> or
 * <a href="https://en.wikipedia.org/wiki/Message_authentication_code">message
 * authentication code</a> verification will use {@link VerifySecureDigestRequest} instead.</p>
 *
 * @see VerifySecureDigestRequest
 * @since JJWT_RELEASE_VERSION
 */
public interface VerifyDigestRequest extends Request<byte[]>, DigestSupplier {
}
