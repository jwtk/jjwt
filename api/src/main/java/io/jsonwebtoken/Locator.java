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

import java.security.Key;

/**
 * A {@link Locator} can return an object referenced in a JWT {@link Header} that is necessary to process
 * the associated JWT.
 *
 * <p>For example, a {@code Locator} implementation can inspect a header's {@code kid} (Key ID) parameter, and use the
 * discovered {@code kid} value to lookup and return the associated {@link Key} instance.  JJWT could then use this
 * {@code key} to decrypt a JWE or verify a JWS signature.</p>
 *
 * @param <T> the type of object that may be returned from the {@link #locate(Header)} method
 * @since JJWT_RELEASE_VERSION
 */
public interface Locator<T> {

    /**
     * Returns an object referenced in the specified {@code header}, or {@code null} if the object couldn't be found.
     *
     * @param header the JWT header to inspect; may be an instance of {@link Header}, {@link JwsHeader} or
     *               {@link JweHeader} depending on if the respective JWT is an unprotected JWT, JWS or JWE.
     * @return an object referenced in the specified {@code header}, or {@code null} if the object couldn't be found.
     */
    T locate(Header header);
}
