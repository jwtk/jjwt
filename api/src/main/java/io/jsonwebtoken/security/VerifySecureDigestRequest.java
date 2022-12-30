package io.jsonwebtoken.security;

import java.security.Key;

/**
 * A request to a {@link SecureDigestAlgorithm} to verify a previously-computed
 * <a href="https://en.wikipedia.org/wiki/Digital_signature">digital signature</a> or
 * <a href="https://en.wikipedia.org/wiki/Message_authentication_code">message
 * authentication code</a>.
 *
 * <p>The content to verify will be available via {@link #getPayload()}, the previously-computed signature or MAC will
 * be available via {@link #getDigest()}, and the verification key will be available via {@link #getKey()}.</p>
 *
 * @param <K> the type of {@link Key} used to verify a digital signature or message authentication code
 * @since JJWT_RELEASE_VERSION
 */
public interface VerifySecureDigestRequest<K extends Key> extends SecureRequest<byte[], K>, VerifyDigestRequest {
}
