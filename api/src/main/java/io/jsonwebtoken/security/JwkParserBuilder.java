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

import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.io.ParserBuilder;

/**
 * A builder to construct a {@link Parser} that can parse {@link Jwk}s.
 * Example usage:
 * <blockquote><pre>
 * Jwk&lt;?&gt; jwk = Jwks.parser()
 *         .provider(aJcaProvider)     // optional
 *         .deserializer(deserializer) // optional
 *         .operationPolicy(policy)    // optional
 *         .build()
 *         .parse(jwkString);</pre></blockquote>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkParserBuilder extends ParserBuilder<Jwk<?>, JwkParserBuilder>, KeyOperationPolicied<JwkParserBuilder> {
}
