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
 * A JwsSigningKeyResolver is invoked by a {@link io.jsonwebtoken.JwtParser JwtParser} if it's provided and the
 * provided JWT is signed.
 * <p/>
 * Implementations of this interfaces must be provided to {@link io.jsonwebtoken.JwtParser JwtParser} when the values
 * embedded in the JWS need to be used to determine the <code>signing key</code> used to sign the JWS.
 *
 * @since 0.4
 */
public interface JwsSigningKeyResolver {

    /**
     * This method is invoked when a {@link io.jsonwebtoken.JwtParser JwtParser} parsed a {@link Jws} and needs
     * to resolve the signing key, based on a value embedded in the {@link JwsHeader} and/or the {@link Claims}
     * <p/>
     * <p>This method will only be invoked if an implementation is provided.</p>
     * <p/>
     * <p>Note that this key <em>MUST</em> be a valid key for the signature algorithm found in the JWT header
     * (as the {@code alg} header parameter).</p>
     *
     * @param header the parsed {@link JwsHeader}
     * @param claims the parsed {@link Claims}
     * @return any object to be used after inspecting the JWS, or {@code null} if no return value is necessary.
     */
    byte[] resolveSigningKey(JwsHeader header, Claims claims);
}
