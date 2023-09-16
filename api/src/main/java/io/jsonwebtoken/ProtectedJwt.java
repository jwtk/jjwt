/*
 * Copyright © 2023 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken;

import io.jsonwebtoken.security.DigestSupplier;

/**
 * A {@code ProtectedJwt} is a {@link Jwt} that is integrity protected via a cryptographic algorithm that produces
 * a cryptographic digest, such as a MAC, Digital Signature or Authentication Tag.
 *
 * <p><b>Cryptographic Digest</b></p>
 * <p>This interface extends DigestSupplier to make available the {@code ProtectedJwt}'s associated cryptographic
 * digest:</p>
 * <ul>
 *     <li>If the JWT is a {@link Jws}, {@link #getDigest() getDigest() } returns the JWS signature.</li>
 *     <li>If the JWT is a {@link Jwe}, {@link #getDigest() getDigest() } returns the AAD Authentication Tag.</li>
 * </ul>
 *
 * @param <H> the type of the JWT protected header
 * @param <P> the type of the JWT payload, either a content byte array or a {@link Claims} instance.
 * @since JJWT_RELEASE_VERSION
 */
public interface ProtectedJwt<H extends ProtectedHeader, P> extends Jwt<H, P>, DigestSupplier {
}
