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

import java.util.Date;

/**
 * A component that is able to read JWT
 * <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4">Claims set</a> values.  This is most naturally
 * supported by a {@link Claims} instance (which implements this interface), but is also supported by
 * a {@link ClaimsBuilder}, which also implements this interface to support the ability to read the builder's values.
 *
 * @see Claims
 * @see ClaimsBuilder
 * @since JJWT_RELEASE_VERSION
 */
public interface ClaimsAccessor {

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.1">
     * <code>iss</code></a> (issuer) value or {@code null} if not present.
     *
     * @return the JWT {@code iss} value or {@code null} if not present.
     */
    String getIssuer();

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.2">
     * <code>sub</code></a> (subject) value or {@code null} if not present.
     *
     * @return the JWT {@code sub} value or {@code null} if not present.
     */
    String getSubject();

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.3">
     * <code>aud</code></a> (audience) value or {@code null} if not present.
     *
     * @return the JWT {@code aud} value or {@code null} if not present.
     */
    String getAudience();

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.4">
     * <code>exp</code></a> (expiration) timestamp or {@code null} if not present.
     *
     * <p>A JWT obtained after this timestamp should not be used.</p>
     *
     * @return the JWT {@code exp} value or {@code null} if not present.
     */
    Date getExpiration();

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.5">
     * <code>nbf</code></a> (not before) timestamp or {@code null} if not present.
     *
     * <p>A JWT obtained before this timestamp should not be used.</p>
     *
     * @return the JWT {@code nbf} value or {@code null} if not present.
     */
    Date getNotBefore();

    /**
     * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.6">
     * <code>iat</code></a> (issued at) timestamp or {@code null} if not present.
     *
     * <p>If present, this value is the timestamp when the JWT was created.</p>
     *
     * @return the JWT {@code iat} value or {@code null} if not present.
     */
    Date getIssuedAt();

    /**
     * Returns the JWTs <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.7">
     * <code>jti</code></a> (JWT ID) value or {@code null} if not present.
     *
     * <p>This value is a CaSe-SenSiTiVe unique identifier for the JWT. If available, this value is expected to be
     * assigned in a manner that ensures that there is a negligible probability that the same value will be
     * accidentally
     * assigned to a different data object.  The ID can be used to prevent the JWT from being replayed.</p>
     *
     * @return the JWT {@code jti} value or {@code null} if not present.
     */
    String getId();

    /**
     * Returns the JWTs claim ({@code claimName}) value as a type {@code requiredType}, or {@code null} if not present.
     *
     * <p>JJWT only converts simple String, Date, Long, Integer, Short and Byte types automatically. Anything more
     * complex is expected to be already converted to your desired type by the JSON
     * {@link io.jsonwebtoken.io.Deserializer Deserializer} implementation. You may specify a custom Deserializer for a
     * JwtParser with the desired conversion configuration via the {@link JwtParserBuilder#deserializeJsonWith} method.
     * See <a href="https://github.com/jwtk/jjwt#custom-json-processor">custom JSON processor</a> for more
     * information. If using Jackson, you can specify custom claim POJO types as described in
     * <a href="https://github.com/jwtk/jjwt#json-jackson-custom-types">custom claim types</a>.
     *
     * @param claimName name of claim
     * @param requiredType the type of the value expected to be returned
     * @param <T> the type of the value expected to be returned
     * @return the JWT {@code claimName} value or {@code null} if not present.
     * @throws RequiredTypeException throw if the claim value is not null and not of type {@code requiredType}
     */
    <T> T get(String claimName, Class<T> requiredType);
}
