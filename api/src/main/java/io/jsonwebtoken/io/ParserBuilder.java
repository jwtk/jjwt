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
package io.jsonwebtoken.io;

import io.jsonwebtoken.lang.Builder;

import java.security.Provider;
import java.util.Map;

/**
 * A {@code ParserBuilder} configures and creates new {@link Parser} instances.
 *
 * @param <T> The resulting parser's {@link Parser#parse parse} output type
 * @param <B> builder type used for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface ParserBuilder<T, B extends ParserBuilder<T, B>> extends Builder<Parser<T>> {

    /**
     * Sets the JCA Provider to use during cryptographic operations, or {@code null} if the
     * JCA subsystem preferred provider should be used.
     *
     * @param provider the JCA Provider to use during cryptographic key factory operations, or {@code null}
     *                 if the JCA subsystem preferred provider should be used.
     * @return the builder for method chaining.
     */
    B provider(Provider provider);

    /**
     * Uses the specified deserializer to convert JSON Strings (UTF-8 byte arrays) into Java Map objects.  The
     * resulting Maps are then used to construct respective JWT objects (JWTs, JWKs, etc).
     *
     * <p>If this method is not called, JJWT will use whatever deserializer it can find at runtime, checking for the
     * presence of well-known implementations such as Jackson, Gson, and org.json.  If one of these is not found
     * in the runtime classpath, an exception will be thrown when the {@link #build()} method is called.
     *
     * @param deserializer the deserializer to use when converting JSON Strings (UTF-8 byte arrays) into Map objects.
     * @return the builder for method chaining.
     */
    B deserializer(Deserializer<Map<String, ?>> deserializer);
}
