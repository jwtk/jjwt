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
package io.jsonwebtoken.security;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A request to an {@link AeadAlgorithm} to perform authenticated encryption with a supplied symmetric
 * {@link SecretKey}, allowing for additional data to be integrity-protected.
 *
 * @see SecureRequest
 * @see AssociatedDataSupplier
 * @since 0.12.0
 */
public interface AeadRequest extends SecureRequest<InputStream, SecretKey>, AssociatedDataSupplier {

    /**
     * Named parameters (setters) used to configure an {@link AeadRequest AeadRequest} instance.
     *
     * @param <P> the instance type returned for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    interface Params<P extends Params<P>> extends SecureRequest.Params<InputStream, SecretKey, P>, OctetStreamPayloadParams<P> {

        /**
         * Sets any &quot;additional associated data&quot; that must be integrity protected (but not encrypted) when
         * performing <a href="https://en.wikipedia.org/wiki/Authenticated_encryption">AEAD encryption or decryption</a>.
         *
         * @param aad the {@code InputStream} containing any associated data that must be integrity protected or
         *            verified during AEAD encryption or decryption.
         * @return the instance for method chaining.
         * @see AeadAlgorithm#encrypt(AeadRequest, AeadResult)
         * @see AeadAlgorithm#decrypt(DecryptAeadRequest, OutputStream)
         */
        P aad(InputStream aad);

        /**
         * Sets any &quot;additional associated data&quot; that must be integrity protected (but not encrypted) or
         * verified when performing
         * <a href="https://en.wikipedia.org/wiki/Authenticated_encryption">AEAD encryption or decryption</a>.
         * <p>
         * This is a convenience method that wraps the specified byte array in an {@link InputStream} and
         * then delegates to {@link #aad(InputStream)}.
         *
         * @param aad any associated data that must be integrity protected or verified during AEAD encryption or
         *            decryption.
         * @return the instance for method chaining.
         * @see #aad(InputStream)
         * @see AeadAlgorithm#encrypt(AeadRequest, AeadResult)
         * @see AeadAlgorithm#decrypt(DecryptAeadRequest, OutputStream)
         */
        default P aad(byte[] aad) {
            InputStream is = Suppliers.BYTES_INPUT_STREAM_FACTORY.apply(aad);
            return aad(is);
        }
    }

    /**
     * A builder for creating new immutable {@link AeadRequest} instances used for AEAD encryption via
     * {@link AeadAlgorithm#encrypt(AeadRequest, AeadResult)}.
     *
     * @since JJWT_RELEASE_VERSION
     */
    interface Builder extends Params<Builder>, io.jsonwebtoken.lang.Builder<AeadRequest> {
    }

    /**
     * Returns a new {@link AeadRequest.Builder} for creating immutable {@link AeadRequest}s used for AEAD encryption
     * via {@link AeadAlgorithm#encrypt(AeadRequest, AeadResult)}.
     *
     * @return a new {@link AeadRequest.Builder} for creating immutable {@link AeadRequest}s used for AEAD encryption
     * via {@link AeadAlgorithm#encrypt(AeadRequest, AeadResult)}.
     * @since JJWT_RELEASE_VERSION
     */
    static AeadRequest.Builder builder() {
        return Suppliers.AEAD_REQUEST_BUILDER.get();
    }
}
