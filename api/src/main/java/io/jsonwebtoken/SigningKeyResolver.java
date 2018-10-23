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

import java.security.Key;

/**
 * A {@code SigningKeyResolver} can be used by a {@link io.jsonwebtoken.JwtParser JwtParser} to find a signing key that
 * should be used to verify a JWS signature.
 *
 * <p>A {@code SigningKeyResolver} is necessary when the signing key is not already known before parsing the JWT and the
 * JWT header or payload (plaintext body or Claims) must be inspected first to determine how to look up the signing key.
 * Once returned by the resolver, the JwtParser will then verify the JWS signature with the returned key.  For
 * example:</p>
 *
 * <pre>
 * Jws&lt;Claims&gt; jws = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
 *         &#64;Override
 *         public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
 *             //inspect the header or claims, lookup and return the signing key
 *             return getSigningKeyBytes(header, claims); //implement me
 *         }})
 *     .parseClaimsJws(compact);
 * </pre>
 *
 * <p>A {@code SigningKeyResolver} is invoked once during parsing before the signature is verified.</p>
 *
 * <h3>SigningKeyResolverAdapter</h3>
 *
 * <p>If you only need to resolve a signing key for a particular JWS (either a plaintext or Claims JWS), consider using
 * the {@link io.jsonwebtoken.SigningKeyResolverAdapter} and overriding only the method you need to support instead of
 * implementing this interface directly.</p>
 *
 * @see io.jsonwebtoken.SigningKeyResolverAdapter
 * @since 0.4
 */
public interface SigningKeyResolver {

    /**
     * Returns the signing key that should be used to validate a digital signature for the Claims JWS with the specified
     * header and claims.
     *
     * @param header the header of the JWS to validate
     * @param claims the claims (body) of the JWS to validate
     * @return the signing key that should be used to validate a digital signature for the Claims JWS with the specified
     * header and claims.
     */
    Key resolveSigningKey(JwsHeader header, Claims claims);

    /**
     * Returns the signing key that should be used to validate a digital signature for the Plaintext JWS with the
     * specified header and plaintext payload.
     *
     * @param header    the header of the JWS to validate
     * @param plaintext the plaintext body of the JWS to validate
     * @return the signing key that should be used to validate a digital signature for the Plaintext JWS with the
     * specified header and plaintext payload.
     */
    Key resolveSigningKey(JwsHeader header, String plaintext);
}
