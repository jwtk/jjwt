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
package io.jsonwebtoken.security;

import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.io.ParserBuilder;

/**
 * A builder to construct a {@link Parser} that can parse {@link JwkSet}s.
 * Example usage:
 * <blockquote><pre>
 * JwkSet jwkSet = Jwks.setParser()
 *         .provider(aJcaProvider)     // optional
 *         .deserializer(deserializer) // optional
 *         .operationPolicy(policy)    // optional
 *         .build()
 *         .parse(jwkSetString);</pre></blockquote>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkSetParserBuilder extends ParserBuilder<JwkSet, JwkSetParserBuilder>, KeyOperationPolicied<JwkSetParserBuilder> {

    /**
     * Sets whether the parser should ignore any encountered JWK it does not support, either because the JWK has an
     * unrecognized {@link Jwk#getType() key type} or the JWK was malformed (missing required parameters, etc).
     * The default value is {@code true} per
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-5">RFC 7517, Section 5</a>, last paragraph:
     * <blockquote><pre>
     *    Implementations SHOULD ignore JWKs within a JWK Set that use "kty"
     *    (key type) values that are not understood by them, that are missing
     *    required members, or for which values are out of the supported
     *    ranges.
     * </pre></blockquote>
     *
     * <p>This value may be set to {@code false} for applications that prefer stricter parsing constraints
     * and wish to react to any {@link MalformedKeyException}s or {@link UnsupportedKeyException}s that could
     * occur.</p>
     *
     * @param ignore whether to ignore unsupported or malformed JWKs encountered during parsing.
     * @return the builder for method chaining.
     */
    JwkSetParserBuilder ignoreUnsupported(boolean ignore);
}
