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
 * An <a href="http://en.wikipedia.org/wiki/Adapter_pattern">Adapter</a> implementation of the
 * {@link JwtHandler} interface that allows for anonymous subclasses to process only the JWT results that are
 * known/expected for a particular use case.
 *
 * <p>All of the methods in this implementation throw exceptions: overridden methods represent
 * scenarios expected by calling code in known situations.  It would be unexpected to receive a JWS or JWT that did
 * not match parsing expectations, so all non-overridden methods throw exceptions to indicate that the JWT
 * input was unexpected.</p>
 *
 * @param <T> the type of object to return to the parser caller after handling the parsed JWT.
 * @since 0.2
 */
public class JwtHandlerAdapter<T> implements JwtHandler<T> {

    @Override
    public T onPlaintextJwt(Jwt<Header, String> jwt) {
        throw new UnsupportedJwtException("Unsigned plaintext JWTs are not supported.");
    }

    @Override
    public T onClaimsJwt(Jwt<Header, Claims> jwt) {
        throw new UnsupportedJwtException("Unsigned Claims JWTs are not supported.");
    }

    @Override
    public T onPlaintextJws(Jws<String> jws) {
        throw new UnsupportedJwtException("Signed plaintext JWSs are not supported.");
    }

    @Override
    public T onClaimsJws(Jws<Claims> jws) {
        throw new UnsupportedJwtException("Signed Claims JWSs are not supported.");
    }
}
