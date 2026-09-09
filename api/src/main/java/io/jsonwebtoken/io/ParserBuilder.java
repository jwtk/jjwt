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
import io.jsonwebtoken.security.Providable;

import java.util.Map;

/**
 * A {@code ParserBuilder} configures and creates new {@link Parser} instances.
 *
 * @param <T> The resulting parser's {@link Parser#parse parse} output type
 * @param <B> builder type used for method chaining
 * @since 0.12.0
 */
public interface ParserBuilder<T, B extends ParserBuilder<T, B>> extends Providable<B>, Builder<Parser<T>> {

    /**
     * Uses the specified {@code Deserializer} to convert JSON Strings (UTF-8 byte streams) into Java Map objects.  The
     * resulting Maps are then used to construct respective JWT objects (JWTs, JWKs, etc).
     *
     * <p>If this method is not called, JJWT will use whatever Deserializer it can find at runtime, checking for the
     * presence of well-known implementations such as Jackson, Gson, and org.json.  If one of these is not found
     * in the runtime classpath, an exception will be thrown when the {@link #build()} method is called.
     *
     * @param deserializer the Deserializer to use when converting JSON Strings (UTF-8 byte streams) into Map objects.
     * @return the builder for method chaining.
     */
    B json(Deserializer<Map<String, ?>> deserializer);
}
