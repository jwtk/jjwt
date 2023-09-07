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

//    /**
//     * Adds the specified key operations to the parser's total set of supported key operations,
//     * replacing any existing operations with the same exact (CaSe-SeNsItIvE) {@link KeyOperation#getId() id}s.
//     *
//     * <p>There may be only one registered {@code KeyOperation} per {@code id}, and the {@code keyOps} collection is
//     * added in iteration order; if a duplicate id is found when iterating the {@code keyOps} collection, the later
//     * {@code KeyOperation} will evict any existing {@code KeyOperation} with the same {@code id}.</p>
//     *
//     * <p><b>Standard Key Operations and Overrides</b></p>
//     *
//     * <p>All JWK standard key operations in {@link Jwks.OP} are supported by default and do not need
//     * to be added via this method, but beware: <b>any {@code KeyOperation} in the {@code keyOps} collection with a
//     * JWK standard {@link Identifiable#getId() id} will replace the JJWT standard {@code KeyOperation} implementation</b>.
//     * This is to allow application developers to favor their own implementations over JJWT's default implementations
//     * if necessary (for example, to support legacy or custom behavior).
//     *
//     * @param keyOps collection of key operations to add to the parser's total set of supported
//     *               key operations, replacing any existing operations with the same
//     *               {@link KeyOperation#getId() id}s.
//     * @return the builder for method chaining.
//     */
//    JwkParserBuilder addOperations(Collection<KeyOperation> keyOps);

}
