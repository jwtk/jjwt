package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A {@code DigestAlgorithm} is a
 * <a href="https://en.wikipedia.org/wiki/Cryptographic_hash_function">Cryptographic Hash Function</a>
 * that computes and verifies cryptographic digests.  There are three types of {@code DigestAlgorithm}s represented
 * by subtypes:
 *
 * <table>
 *     <caption>Types of {@code DigestAlgorithm}s</caption>
 *     <thead>
 *         <tr>
 *             <th>Algorithm Type</th>
 *             <th>Subtype</th>
 *             <th>Security Model</th>
 *         </tr>
 *     </thead>
 *     <tbody>
 *         <tr>
 *             <td>Hash</td>
 *             <td>{@link HashAlgorithm}</td>
 *             <td>Unsecured (unkeyed), does not require a key to compute or verify digests.</td>
 *         </tr>
 *         <tr>
 *             <td>Message Authentication Code (MAC)</td>
 *             <td>{@link MacAlgorithm}</td>
 *             <td>Requires a {@link SecretKey} to both compute and verify digests.</td>
 *         </tr>
 *         <tr>
 *             <td>Digital Signature</td>
 *             <td>{@link SignatureAlgorithm}</td>
 *             <td>Requires a {@link PrivateKey} to compute and {@link PublicKey} to verify digests.</td>
 *         </tr>
 *     </tbody>
 * </table>
 *
 * <p><b>JWA Standard Implementations</b></p>
 *
 * <p>Constant definitions and utility methods for all JWA (RFC 7518) standard
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3">Cryptographic Algorithms for Digital Signatures and
 * MACs</a> that may be represented in a JWS {@code alg}orithm header
 * are available via the {@link JwsAlgorithms} utility class.</p>
 *
 * <p><b>JWS &quot;alg&quot; identifier</b></p>
 *
 * <p>{@code DigestAlgorithm} extends {@link Identifiable}: the value returned from
 * {@link Identifiable#getId() getId()} will be used as the JWT standard identifier where required, for example as a
 * JWS &quot;alg&quot; protected header value.</p>
 *
 * @param <R> the type of {@link Request} used when computing a digest.
 * @param <V> the type of {@link VerifyDigestRequest} used when verifying a digest.
 * @since JJWT_RELEASE_VERSION
 */
public interface DigestAlgorithm<R extends Request<byte[]>, V extends VerifyDigestRequest> extends Identifiable {

    /**
     * Returns a cryptographic digest of the request {@link Request#getPayload() payload}.
     *
     * @param request the request containing the data to be hashed, mac'd or signed.
     * @return a cryptographic digest of the request {@link Request#getPayload() payload}.
     * @throws SecurityException if there is invalid key input or a problem during digest creation.
     */
    byte[] digest(R request) throws SecurityException;

    /**
     * Returns {@code true} if the provided {@link VerifyDigestRequest#getDigest() digest} matches the expected value
     * for the given {@link VerifyDigestRequest#getPayload() payload}, {@code false} otherwise.
     *
     * @param request the request containing the {@link VerifyDigestRequest#getDigest() digest} to verify for the
     *                associated {@link VerifyDigestRequest#getPayload() payload}.
     * @return {@code true} if the provided {@link VerifyDigestRequest#getDigest() digest} matches the expected value
     * for the given {@link VerifyDigestRequest#getPayload() payload}, {@code false} otherwise.
     * @throws SecurityException if there is an invalid key input or a problem that won't allow digest verification.
     */
    boolean verify(V request) throws SecurityException;
}
