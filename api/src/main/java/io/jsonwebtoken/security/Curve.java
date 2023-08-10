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
 * <p>The JWT specifications define standard curves in the {@code JSON Web Key Elliptic Curve Registry}.  The
 * registry contains curves defined in both
 * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-7.6">RFC 7518, Section 7.6<a>
 * (for Weierstrass Elliptic Curves) and
 * <a href="https://www.rfc-editor.org/rfc/rfc8037#section-5">RFC 8037, Section 5</a> (for Edwards Elliptic Curves).
 *
 * <p><b>Curve Identifier</b></p>
 *
 * <p>This interface extends {@link Identifiable}; the value returned from the {@link #getId()} is the
 * curve's CaSe-SeNsItIvE unique {@code Curve Name} defined in the {@code JSON Web Key Elliptic Curve Registry}.</p>
 *
 * <p><b>KeyPair Generation</b></p>
 *
 * <p>A secure-random KeyPair of sufficient strength on the curve may be obtained with its {@link #keyPair()} builder.</p>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface Curve extends Identifiable, KeyPairBuilderSupplier {
}
