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
 * scenarios expected by calling code in known situations.  It would be unexpected to receive a JWT that did
 * not match parsing expectations, so all non-overridden methods throw exceptions to indicate that the JWT
 * input was unexpected.</p>
 *
 * @param <T> the type of object to return to the parser caller after handling the parsed JWT.
 * @since 0.2
 */
public abstract class JwtHandlerAdapter<T> extends SupportedJwtVisitor<T> implements JwtHandler<T> {

    /**
     * Default constructor, does not initialize any internal state.
     */
    public JwtHandlerAdapter() {
    }

    @Override
    public T onUnsecuredContent(Jwt<Header, byte[]> jwt) {
        return onContentJwt(jwt); // bridge for existing implementations
    }

    @Override
    public T onUnsecuredClaims(Jwt<Header, Claims> jwt) {
        return onClaimsJwt(jwt);
    }

    @Override
    public T onVerifiedContent(Jws<byte[]> jws) {
        return onContentJws(jws);
    }

    @Override
    public T onVerifiedClaims(Jws<Claims> jws) {
        return onClaimsJws(jws);
    }

    @Override
    public T onDecryptedContent(Jwe<byte[]> jwe) {
        return onContentJwe(jwe);
    }

    @Override
    public T onDecryptedClaims(Jwe<Claims> jwe) {
        return onClaimsJwe(jwe);
    }

    @Override
    public T onContentJwt(Jwt<Header, byte[]> jwt) {
        return super.onUnsecuredContent(jwt);
    }

    @Override
    public T onClaimsJwt(Jwt<Header, Claims> jwt) {
        return super.onUnsecuredClaims(jwt);
    }

    @Override
    public T onContentJws(Jws<byte[]> jws) {
        return super.onVerifiedContent(jws);
    }

    @Override
    public T onClaimsJws(Jws<Claims> jws) {
        return super.onVerifiedClaims(jws);
    }

    @Override
    public T onContentJwe(Jwe<byte[]> jwe) {
        return super.onDecryptedContent(jwe);
    }

    @Override
    public T onClaimsJwe(Jwe<Claims> jwe) {
        return super.onDecryptedClaims(jwe);
    }
}
