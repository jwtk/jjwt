/*
 * Copyright © 2022 jsonwebtoken.io
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
package io.jsonwebtoken.security;

import java.net.URI;

/**
 * A canonical cryptographic digest of a JWK as defined by the
 * <a href="https://www.rfc-editor.org/rfc/rfc7638">JSON Web Key (JWK) Thumbprint</a> specification.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkThumbprint {

    /**
     * Returns the {@link HashAlgorithm} used to compute the thumbprint.
     *
     * @return the {@link HashAlgorithm} used to compute the thumbprint.
     */
    HashAlgorithm getHashAlgorithm();

    /**
     * Returns the actual thumbprint (aka digest) byte array value.
     *
     * @return the actual thumbprint (aka digest) byte array value.
     */
    byte[] toByteArray();

    /**
     * Returns the canonical URI representation of this thumbprint as defined by the
     * <a href="https://www.rfc-editor.org/rfc/rfc9278.html">JWK Thumbprint URI</a> specification.
     *
     * @return a canonical JWK Thumbprint URI
     */
    URI toURI();

    /**
     * Returns the {@link #toByteArray()} value as a Base64URL-encoded string.
     */
    String toString();
}
