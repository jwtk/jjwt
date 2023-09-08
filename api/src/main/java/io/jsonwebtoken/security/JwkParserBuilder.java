/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Builder;

import java.security.Provider;
import java.util.Map;

/**
 * A builder to construct a {@link JwkParser}.  Example usage:
 * <blockquote><pre>
 * Jwk&lt;?&gt; jwk = Jwks.parser()
 *         .provider(aJcaProvider)            // optional
 *         .deserializeJsonWith(deserializer) // optional
 *         .build()
 *         .parse(jwkString);</pre></blockquote>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkParserBuilder extends Builder<JwkParser> {

    /**
     * Sets the JCA Provider to use during cryptographic key factory operations, or {@code null} if the
     * JCA subsystem preferred provider should be used.
     *
     * @param provider the JCA Provider to use during cryptographic key factory operations, or {@code null}
     *                 if the JCA subsystem preferred provider should be used.
     * @return the builder for method chaining.
     */
    JwkParserBuilder provider(Provider provider);

    /**
     * Uses the specified deserializer to convert JSON Strings (UTF-8 byte arrays) into Java Map objects.  The
     * resulting Maps are then used to construct {@link Jwk} instances.
     *
     * <p>If this method is not called, JJWT will use whatever deserializer it can find at runtime, checking for the
     * presence of well-known implementations such Jackson, Gson, and org.json.  If one of these is not found
     * in the runtime classpath, an exception will be thrown when the resulting {@link JwkParser}'s
     * {@link JwkParser#parse(String) parse(json)} method is called.
     *
     * @param deserializer the deserializer to use when converting JSON Strings (UTF-8 byte arrays) into Map objects.
     * @return the builder for method chaining.
     */
    JwkParserBuilder deserializeJsonWith(Deserializer<Map<String, ?>> deserializer);

    /**
     * Sets the parser's key operation policy that determines which {@link KeyOperation}s may be assigned to parsed
     * JWKs. Unless overridden by this method, the parser uses the default RFC-recommended policy where:
     * <ul>
     *     <li>All {@link Jwks.OP RFC-standard key operations} are supported.</li>
     *     <li>Multiple unrelated operations may <b>not</b> be assigned to the JWK per the
     *     <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">RFC 7517, Section 4.3</a> recommendation:
     * <blockquote><pre>
     * Multiple unrelated key operations SHOULD NOT be specified for a key
     * because of the potential vulnerabilities associated with using the
     * same key with multiple algorithms.
     * </pre></blockquote></li>
     * </ul>
     *
     * <p>If you wish to enable a different policy, perhaps to support additional custom {@code KeyOperation} values,
     * one can be created by using the {@link Jwks.OP#policy()} builder, or by implementing the
     * {@link KeyOperationPolicy} interface directly.</p>
     *
     * @param policy the policy to use to determine which {@link KeyOperation}s may be assigned to parsed JWKs.
     * @return the builder for method chaining.
     * @throws IllegalArgumentException if {@code policy} is null
     */
    JwkParserBuilder operationPolicy(KeyOperationPolicy policy) throws IllegalArgumentException;

}
