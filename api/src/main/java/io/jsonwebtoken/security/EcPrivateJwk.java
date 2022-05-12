/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * JWK representation of an {@link ECPrivateKey} as defined by the JWA (RFC 7518) specification sections on
 * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2">Parameters for Elliptic Curve Keys</a> and
 * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2">Parameters for Elliptic Curve Private Keys</a>.
 *
 * <p>Note that the various EC-specific properties are not available as separate dedicated getter methods, as most Java
 * applications should rarely, if ever, need to access these individual key properties since they typically represent
 * internal key material and/or implementation details.</p>
 *
 * <p>Even so, because they exist and are readable by nature of every JWK being a {@link java.util.Map Map}, the
 * properties are still accessible in two different ways:</p>
 * <ul>
 *     <li>Via the standard {@code Map} {@link #get(Object) get} method using an appropriate JWK parameter id,
 *     e.g. {@code jwk.get("x")}, {@code jwk.get("y")}, etc.</li>
 *     <li>Via the various getter methods on the {@link ECPrivateKey} instance returned by {@link #toKey()}.</li>
 * </ul>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface EcPrivateJwk extends PrivateJwk<ECPrivateKey, ECPublicKey, EcPublicJwk> {
}
