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

/**
 * A Parser converts character input into a Java object.
 *
 * <p>Semantically, this interface might have been more accurately named
 * <a href="https://en.wikipedia.org/wiki/Marshalling_(computer_science)">Unmarshaller</a> because it technically
 * converts a content stream into a Java object. However, the {@code Parser} name was chosen for consistency with the
 * {@link io.jsonwebtoken.JwtParser JwtParser} concept (which is a 'real' parser that scans text for tokens).  This
 * helps avoid confusion when trying to find similar concepts in the JJWT API by using the same taxonomy, for
 * example:</p>
 * <ul>
 *     <li>{@link io.jsonwebtoken.Jwts#parser() Jwts.parser()}</li>
 *     <li>{@link io.jsonwebtoken.security.Jwks#parser() Jwks.parser()}</li>
 *     <li>{@link io.jsonwebtoken.security.Jwks#setParser() Jwks.setParser()}</li>
 * </ul>
 *
 * @param <T> the instance type created after parsing/unmarshalling
 * @since JJWT_RELEASE_VERSION
 */
public interface Parser<T> {

    /**
     * Parse the specified input into a Java object.
     *
     * @param input the string to parse into a Java object.
     * @return the Java object represented by the specified {@code input} stream.
     */
    T parse(String input);

}
