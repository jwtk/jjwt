package io.jsonwebtoken;

import io.jsonwebtoken.security.DigestSupplier;

/**
 * A {@code ProtectedJwt} is a {@link Jwt} that is integrity protected via a cryptographic algorithm that produces
 * a cryptographic digest, such as a MAC, Digital Signature or Authentication Tag.
 *
 * <p><b>Cryptographic Digest</b></p>
 * <p>This interface extends DigestSupplier to make available the {@code ProtectedJwt}'s associated cryptographic
 * digest:
 * <ul>
 *     <li>If the JWT is a {@link Jws}, {@link #getDigest() getDigest() } returns the JWS signature.</li>
 *     <li>If the JWT is a {@link Jwe}, {@link #getDigest() getDigest() } returns the AAD Authentication Tag.</li>
 * </ul>
 * </p>
 *
 * @param <H> the type of the JWT protected header
 * @param <P> the type of the JWT payload, either a content byte array or a {@link Claims} instance.
 * @since JJWT_RELEASE_VERSION
 */
public interface ProtectedJwt<H extends ProtectedHeader, P> extends Jwt<H, P>, DigestSupplier {
}
