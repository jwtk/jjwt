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
import io.jsonwebtoken.security.X509Mutator;

import java.net.URI;
import java.util.Set;

/**
 * Mutation (modifications) to a {@link ProtectedHeader Header} instance.
 *
 * @param <T> the mutator subtype, for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface ProtectedHeaderMutator<T extends ProtectedHeaderMutator<T>> extends HeaderMutator<T>, X509Mutator<T> {

    /**
     * Sets the {@code jku} (JWK Set URL) value that refers to a
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-5">JWK Set</a>
     * resource containing JSON-encoded Public Keys, or {@code null} if not present.  When set for a
     * {@link JwsHeader}, the first public key in the JWK Set <em>must</em> be the public key complement of the
     * private key used to sign the JWS. When set for a {@link JweHeader}, the first public key in the JWK Set
     * <em>must</em> be the public key used during encryption.
     *
     * @param uri a URI that refers to a <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-5">JWK Set</a>
     *            resource containing JSON-encoded Public Keys
     * @return the header for method chaining
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2">JWS JWK Set URL</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.4">JWE JWK Set URL</a>
     */
    T setJwkSetUrl(URI uri);

    /**
     * Sets the {@code jwk} (JSON Web Key) associated with the JWT.  When set for a {@link JwsHeader}, the
     * {@code jwk} is the public key complement of the private key used to digitally sign the JWS.  When set for a
     * {@link JweHeader}, the {@code jwk} is the public key to which the JWE was encrypted, and may be used to
     * determine the private key needed to decrypt the JWE.
     *
     * @param jwk the {@code jwk} (JSON Web Key) associated with the header.
     * @return the header for method chaining
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3">JWS <code>jwk</code> (JSON Web Key) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.5">JWE <code>jwk</code> (JSON Web Key) Header Parameter</a>
     */
    T setJwk(PublicJwk<?> jwk);

    /**
     * Sets the JWT case-sensitive {@code kid} (Key ID) header value. A {@code null} value will remove the property
     * from the JSON map.
     *
     * <p>The keyId header parameter is a hint indicating which key was used to secure a JWS or JWE.  This parameter
     * allows originators to explicitly signal a change of key to recipients.  The structure of the keyId value is
     * unspecified. Its value MUST be a case-sensitive string.</p>
     *
     * <p>When used with a JWK, the keyId value is used to match a JWK {@code keyId} parameter value.</p>
     *
     * @param kid the case-sensitive JWS {@code kid} header value or {@code null} to remove the property from the JSON map.
     * @return the header instance for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4">JWS Key ID</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6">JWE Key ID</a>
     */
    T setKeyId(String kid);

    /**
     * Sets the header parameter names that use extensions to the JWT or JWA specification that <em>MUST</em>
     * be understood and supported by the JWT recipient. A {@code null} value will remove the
     * property from the JSON map.
     *
     * @param crit the header parameter names that use extensions to the JWT or JWA specification that <em>MUST</em>
     *             be understood and supported by the JWT recipient.
     * @return the header for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11">JWS <code>crit</code> (Critical) Header Parameter</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.13">JWS <code>crit</code> (Critical) Header Parameter</a>
     */
    T setCritical(Set<String> crit);
}
