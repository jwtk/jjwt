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

import io.jsonwebtoken.security.PublicJwk;
import io.jsonwebtoken.security.X509Accessor;

import java.net.URI;
import java.util.Set;

/**
 * A JWT header that is integrity protected, either by JWS digital signature or JWE AEAD encryption.
 *
 * @see JwsHeader
 * @see JweHeader
 * @since JJWT_RELEASE_VERSION
 */
public interface ProtectedHeader extends Header, X509Accessor {

    /**
     * Returns the {@code jku} (JWK Set URL) value that refers to a
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-5">JWK Set</a>
     * resource containing JSON-encoded Public Keys, or {@code null} if not present.  When present in a
     * {@link JwsHeader}, the first public key in the JWK Set <em>must</em> be the public key complement of the private
     * key used to sign the JWS. When present in a {@link JweHeader}, the first public key in the JWK Set <em>must</em>
     * be the public key used during encryption.
     *
     * @return a URI that refers to a <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-5">JWK Set</a>
     * resource for a set of JSON-encoded Public Keys, or {@code null} if not present.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2">JWS JWK Set URL</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.4">JWE JWK Set URL</a>
     */
    URI getJwkSetUrl();

    /**
     * Returns the {@code jwk} (JSON Web Key) associated with the JWT.  When present in a {@link JwsHeader}, the
     * {@code jwk} is the public key complement of the private key used to digitally sign the JWS.  When present in a
     * {@link JweHeader}, the {@code jwk} is the public key to which the JWE was encrypted, and may be used to
     * determine the private key needed to decrypt the JWE.
     *
     * @return the {@code jwk} (JSON Web Key) associated with the header.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3">JWS {@code jwk} (JSON Web Key) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.5">JWE {@code jwk} (JSON Web Key) Header Parameter</a>
     */
    PublicJwk<?> getJwk();

    /**
     * Returns the JWT case-sensitive {@code kid} (Key ID) header value or {@code null} if not present.
     *
     * <p>The keyId header parameter is a hint indicating which key was used to secure a JWS or JWE.  This
     * parameter allows originators to explicitly signal a change of key to recipients.  The structure of the keyId
     * value is unspecified. Its value is a CaSe-SeNsItIvE string.</p>
     *
     * <p>When used with a JWK, the keyId value is used to match a JWK {@code keyId} parameter value.</p>
     *
     * @return the case-sensitive {@code kid} header value or {@code null} if not present.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4">JWS Key ID</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.6">JWE Key ID</a>
     */
    String getKeyId();

    /**
     * Returns the header parameter names that use extensions to the JWT or JWA specification that <em>MUST</em>
     * be understood and supported by the JWT recipient, or {@code null} if not present.
     *
     * @return the header parameter names that use extensions to the JWT or JWA specification that <em>MUST</em>
     * be understood and supported by the JWT recipient, or {@code null} if not present.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11">JWS {@code crit} (Critical) Header Parameter</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.13">JWS {@code crit} (Critical) Header Parameter</a>
     */
    Set<String> getCritical();
}
