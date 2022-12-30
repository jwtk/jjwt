package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * A {@link SecureDigestAlgorithm} that uses symmetric {@link SecretKey}s to both compute and verify digests as
 * <a href="https://en.wikipedia.org/wiki/Message_authentication_code">message authentication codes</a> (MACs).
 *
 * <p><b>Key Strength</b></p>
 *
 * <p>MAC algorithm strength is in part attributed to how difficult it is to discover the secret key.
 * As such, MAC algorithms usually require keys of a minimum length to ensure the keys are difficult to discover
 * and the algorithm's security properties are maintained.</p>
 *
 * <p>The {@code MacAlgorithm} interface extends the {@link KeyLengthSupplier} interface to represent
 * the length in bits (<em>not bytes</em>) a key must have to be used with its implementation.  If you do not want to
 * worry about lengths and parameters of keys required for an algorithm, it is often easier to automatically generate
 * a key that adheres to the algorithms requirements, as discussed below.</p>
 *
 * <p><b>Key Generation</b></p>
 *
 * <p>{@code MacAlgorithm} extends {@link KeyBuilderSupplier} to enable {@link SecretKey} generation.
 * Each {@code MacAlgorithm} algorithm instance will return a {@link KeyBuilder} that ensures any created keys will
 * have a sufficient length and any algorithm parameters required by that algorithm. For example:</p>
 *
 * <blockquote><pre>
 * SecretKey key = macAlgorithm.keyBuilder().build();</pre></blockquote>
 *
 * <p>The resulting {@code key} is guaranteed to have the correct algorithm parameters and strength/length necessary for
 * that exact {@code macAlgorithm} instance.</p>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface MacAlgorithm extends SecureDigestAlgorithm<SecretKey, SecretKey>,
        KeyBuilderSupplier<SecretKey, SecretKeyBuilder>, KeyLengthSupplier {
}
