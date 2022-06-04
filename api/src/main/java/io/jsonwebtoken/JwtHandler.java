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
 * A JwtHandler is invoked by a {@link io.jsonwebtoken.JwtParser JwtParser} after parsing a JWT to indicate the exact
 * type of JWT, JWS or JWE parsed.
 *
 * @param <T> the type of object to return to the parser caller after handling the parsed JWT.
 * @since 0.2
 */
public interface JwtHandler<T> {

    /**
     * This method is invoked when a {@link io.jsonwebtoken.JwtParser JwtParser} determines that the parsed JWT is
     * a plaintext Unprotected JWT.  A plaintext JWT has a non-JSON byte array body payload that is not
     * cryptographically signed or encrypted.
     *
     * @param jwt the parsed plaintext JWT
     * @return any object to be used after inspecting the JWT, or {@code null} if no return value is necessary.
     */
    T onPayloadJwt(Jwt<UnprotectedHeader, byte[]> jwt);

    /**
     * This method is invoked when a {@link io.jsonwebtoken.JwtParser JwtParser} determines that the parsed JWT is
     * a Claims JWT.  A Claims JWT has a {@link Claims} body that is not cryptographically signed or encrypted.
     *
     * @param jwt the parsed claims JWT
     * @return any object to be used after inspecting the JWT, or {@code null} if no return value is necessary.
     */
    T onClaimsJwt(Jwt<UnprotectedHeader, Claims> jwt);

    /**
     * This method is invoked when a {@link io.jsonwebtoken.JwtParser JwtParser} determines that the parsed JWT is
     * a plaintext JWS.  A plaintext JWS is a JWT with a (non-JSON) byte array body (payload) that has been
     * cryptographically signed.
     *
     * <p>This method will only be invoked if the cryptographic signature can be successfully verified.</p>
     *
     * @param jws the parsed plaintext JWS
     * @return any object to be used after inspecting the JWS, or {@code null} if no return value is necessary.
     */
    T onPlaintextJws(Jws<byte[]> jws);

    /**
     * This method is invoked when a {@link io.jsonwebtoken.JwtParser JwtParser} determines that the parsed JWT is
     * a valid Claims JWS.  A Claims JWS is a JWT with a {@link Claims} body that has been cryptographically signed.
     *
     * <p>This method will only be invoked if the cryptographic signature can be successfully verified.</p>
     *
     * @param jws the parsed claims JWS
     * @return any object to be used after inspecting the JWS, or {@code null} if no return value is necessary.
     */
    T onClaimsJws(Jws<Claims> jws);

    /**
     * This method is invoked when a {@link io.jsonwebtoken.JwtParser JwtParser} determines that the parsed JWT is
     * a plaintext JWE.  A plaintext JWE is a JWE with a byte array (non-JSON) body (payload) that has been
     * encrypted.
     *
     * <p>This method will only be invoked if the plaintext JWE can be successfully decrypted.</p>
     *
     * @param jwe the parsed plaintext jwe
     * @return any object to be used after inspecting the JWE, or {@code null} if no return value is necessary.
     * @since JJWT_RELEASE_VERSION
     */
    T onPlaintextJwe(Jwe<byte[]> jwe);

    /**
     * This method is invoked when a {@link io.jsonwebtoken.JwtParser JwtParser} determines that the parsed JWT is
     * a valid Claims JWE.  A Claims JWE is a JWT with a {@link Claims} body that has been encrypted.
     *
     * <p>This method will only be invoked if the Claims JWE can be successfully decrypted.</p>
     *
     * @param jwe the parsed claims jwe
     * @return any object to be used after inspecting the JWE, or {@code null} if no return value is necessary.
     * @since JJWT_RELEASE_VERSION
     */
    T onClaimsJwe(Jwe<Claims> jwe);

}
