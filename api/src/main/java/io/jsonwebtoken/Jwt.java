/*
 * Copyright (C) 2014 jsonwebtoken.io
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
 * An expanded (not compact/serialized) JSON Web Token.
 *
 * @param <B> the type of the JWT body contents, either a String or a {@link Claims} instance.
 *
 * @since 0.1
 */
public interface Jwt<H extends Header, B> {

    /**
     * Returns the JWT {@link Header} or {@code null} if not present.
     *
     * @return the JWT {@link Header} or {@code null} if not present.
     */
    H getHeader();

    /**
     * Returns the JWT body, either a {@code String} or a {@code Claims} instance.
     *
     * @return the JWT body, either a {@code String} or a {@code Claims} instance.
     */
    B getBody();
}
