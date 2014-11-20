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
 * {@link SigningKeyResolver} interface that allows subclasses to process only the type of Jws body that
 * are known/expected for a particular case.
 *
 * <p>All of the methods in this implementation throw exceptions: overridden methods represent
 * scenarios expected by calling code in known situations.  It would be unexpected to receive a JWS or JWT that did
 * not match parsing expectations, so all non-overridden methods throw exceptions to indicate that the JWT
 * input was unexpected.</p>
 *
 * @since 0.4
 */
public class SigningKeyResolverAdapter implements SigningKeyResolver {

    @Override
    public byte[] resolveSigningKey(JwsHeader header, Claims claims) {
        throw new UnsupportedJwtException("Resolving signing keys with claims are not supported.");
    }

    @Override
    public byte[] resolveSigningKey(JwsHeader header, String payload) {
        throw new UnsupportedJwtException("Resolving signing keys with plaintext payload are not supported.");
    }
}
