/*
 * Copyright © 2022 jsonwebtoken.io
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
package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;

/**
 * A cryptographic Elliptic Curve for use with digital signature or key agreement algorithms.
 *
 * <p><b>Curve Identifier</b></p>
 *
 * <p>This interface extends {@link Identifiable}; the value returned from {@link #getId()} will
 * be used as the JWK
 * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1"><code>crv</code></a> value.</p>
 *
 * <p><b>KeyPair Generation</b></p>
 *
 * <p>A secure-random KeyPair of sufficient strength on the curve may be obtained with its {@link #keyPair()} builder.</p>
 *
 * <p><b>Standard Implementations</b></p>
 *
 * <p>Constants for all JWA standard Curves are available via the {@link Jwks.CRV} registry.</p>
 *
 * @see Jwks.CRV
 * @since JJWT_RELEASE_VERSION
 */
public interface Curve extends Identifiable, KeyPairBuilderSupplier {
}
