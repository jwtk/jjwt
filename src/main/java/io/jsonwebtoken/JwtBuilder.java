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
import java.util.Map;

/**
 * A builder for constructing JWTs.
 *
 * @since 0.1
 */
public interface JwtBuilder {

    //replaces any existing header with the specified header.

    /**
     * Sets (and replaces) any existing header with the specified header.  If you do not want to replace the existing
     * header and only want to append to it, use the {@link #setHeaderParams(java.util.Map)} method instead.
     *
     * @param header the header to set (and potentially replace any existing header).
     * @return the builder for method chaining.
     */
    JwtBuilder setHeader(Header header);

    /**
     * Sets (and replaces) any existing header with the specified header.  If you do not want to replace the existing
     * header and only want to append to it, use the {@link #setHeaderParams(java.util.Map)} method instead.
     *
     * @param header the header to set (and potentially replace any existing header).
     * @return the builder for method chaining.
     */
    JwtBuilder setHeader(Map<String, Object> header);

    /**
     * Applies the specified name/value pairs to the header.  If a header does not yet exist at the time this method
     * is called, one will be created automatically before applying the name/value pairs.
     *
     * @param params the header name/value pairs to append to the header.
     * @return the builder for method chaining.
     */
    JwtBuilder setHeaderParams(Map<String, Object> params);

    //sets the specified header parameter, overwriting any previous value under the same name.

    /**
     * Applies the specified name/value pair to the header.  If a header does not yet exist at the time this method
     * is called, one will be created automatically before applying the name/value pair.
     *
     * @param name  the header parameter name
     * @param value the header parameter value
     * @return the builder for method chaining.
     */
    JwtBuilder setHeaderParam(String name, Object value);

    /**
     * Sets the JWT's payload to be a plaintext (non-JSON) string.  If you want the JWT body to be JSON, use the
     * {@link #setClaims(Claims)} or {@link #setClaims(java.util.Map)} methods instead.
     *
     * <p>The payload and claims properties are mutually exclusive - only one of the two may be used.</p>
     *
     * @param payload the plaintext (non-JSON) string that will be the body of the JWT.
     * @return the builder for method chaining.
     */
    JwtBuilder setPayload(String payload);

    /**
     * Sets the JWT payload to be a JSON Claims instance.  If you do not want the JWT body to be JSON and instead want
     * it to be a plaintext string, use the {@link #setPayload(String)} method instead.
     *
     * <p>The payload and claims properties are mutually exclusive - only one of the two may be used.</p>
     *
     * @param claims the JWT claims to be set as the JWT body.
     * @return the builder for method chaining.
     */
    JwtBuilder setClaims(Claims claims);

    /**
     * Sets the JWT payload to be a JSON Claims instance populated by the specified name/value pairs.  If you do not
     * want the JWT body to be JSON and instead want it to be a plaintext string, use the {@link #setPayload(String)}
     * method instead.
     *
     * <p>The payload* and claims* properties are mutually exclusive - only one of the two may be used.</p>
     *
     * @param claims the JWT claims to be set as the JWT body.
     * @return the builder for method chaining.
     */
    JwtBuilder setClaims(Map<String, Object> claims);

    /**
     * Signs the constructed JWT using the specified algorithm with the specified key, producing a JWS.
     *
     * @param alg       the JWS algorithm to use to digitally sign the JWT, thereby producing a JWS.
     * @param secretKey the algorithm-specific signing key to use to digitally sign the JWT.
     * @return the builder for method chaining.
     */
    JwtBuilder signWith(SignatureAlgorithm alg, byte[] secretKey);

    /**
     * Signs the constructed JWT using the specified algorithm with the specified key, producing a JWS.
     *
     * <p>This is a convenience method: the string argument is first BASE64-decoded to a byte array and this resulting
     * byte array is used to invoke {@link #signWith(SignatureAlgorithm, byte[])}.</p>
     *
     * @param alg                    the JWS algorithm to use to digitally sign the JWT, thereby producing a JWS.
     * @param base64EncodedSecretKey the BASE64-encoded algorithm-specific signing key to use to digitally sign the
     *                               JWT.
     * @return the builder for method chaining.
     */
    JwtBuilder signWith(SignatureAlgorithm alg, String base64EncodedSecretKey);

    /**
     * Signs the constructed JWT using the specified algorithm with the specified key, producing a JWS.
     *
     * @param alg the JWS algorithm to use to digitally sign the JWT, thereby producing a JWS.
     * @param key the algorithm-specific signing key to use to digitally sign the JWT.
     * @return the builder for method chaining.
     */
    JwtBuilder signWith(SignatureAlgorithm alg, Key key);

    /**
     * Actually builds the JWT and serializes it to a compact, URL-safe string according to the
     * <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-7">JWT Compact Serialization</a>
     * rules.
     *
     * @return A compact URL-safe JWT string.
     */
    String compact();
}
