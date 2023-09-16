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
package io.jsonwebtoken;

/**
 * An object that may be uniquely identified by an {@link #getId() id} relative to other instances of the same type.
 *
 * <p>The following table indicates how various JWT or JWK {@link #getId() getId()} values are used.</p>
 *
 * <table>
 * <caption>JWA Identifiable Concepts</caption>
 * <thead>
 * <tr>
 * <th>JJWT Type</th>
 * <th>How {@link #getId()} is Used</th>
 * </tr>
 * </thead>
 * <tbody>
 * <tr>
 * <td>{@link io.jsonwebtoken.Claims Claims}</td>
 * <td>JWT's <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7">{@code jti} (JWT ID)</a>
 * claim.</td>
 * </tr>
 * <tr>
 * <td>{@link io.jsonwebtoken.security.Jwk Jwk}</td>
 * <td>JWK's <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5">{@code kid} (Key ID)</a>
 * parameter value.</td>
 * </tr>
 * <tr>
 * <td>{@link io.jsonwebtoken.security.Curve Curve}</td>
 * <td>JWK's <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1">{@code crv} (Curve)</a>
 * parameter value.</td>
 * </tr>
 * <tr>
 * <td>{@link io.jsonwebtoken.io.CompressionAlgorithm CompressionAlgorithm}</td>
 * <td>JWE protected header's
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3">{@code zip} (Compression Algorithm)</a>
 * parameter value.</td>
 * </tr>
 * <tr>
 * <td>{@link io.jsonwebtoken.security.HashAlgorithm HashAlgorithm}</td>
 * <td>Within a {@link io.jsonwebtoken.security.JwkThumbprint JwkThumbprint}'s URI value.</td>
 * </tr>
 * <tr>
 * <td>{@link io.jsonwebtoken.security.MacAlgorithm MacAlgorithm}</td>
 * <td>JWS protected header's
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">{@code alg} (Algorithm)</a> parameter value.</td>
 * </tr>
 * <tr>
 * <td>{@link io.jsonwebtoken.security.SignatureAlgorithm SignatureAlgorithm}</td>
 * <td>JWS protected header's
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">{@code alg} (Algorithm)</a> parameter value.</td>
 * </tr>
 * <tr>
 * <td>{@link io.jsonwebtoken.security.KeyAlgorithm KeyAlgorithm}</td>
 * <td>JWE protected header's
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1">{@code alg} (Key Management Algorithm)</a>
 * parameter value.</td>
 * </tr>
 * <tr>
 * <td>{@link io.jsonwebtoken.security.AeadAlgorithm AeadAlgorithm}</td>
 * <td>JWE protected header's
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">{@code enc} (Encryption Algorithm)</a>
 * parameter value.</td>
 * </tr>
 * </tbody>
 * </table>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface Identifiable {

    /**
     * Returns the unique string identifier of the associated object.
     *
     * @return the unique string identifier of the associated object.
     */
    String getId();
}
