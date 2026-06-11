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

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.lang.Assert;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Consumer;

/**
 * A cryptographic algorithm that performs
 * <a href="https://en.wikipedia.org/wiki/Authenticated_encryption">Authenticated encryption with additional data</a>.
 * Per <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2">JWE RFC 7516, Section 4.1.2</a>, all JWEs
 * <em>MUST</em> use an AEAD algorithm to encrypt or decrypt the JWE payload/content.  Consequently, all
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1">JWA &quot;enc&quot; algorithms</a> are AEAD
 * algorithms, and they are accessible as concrete instances via {@link io.jsonwebtoken.Jwe.alg Jwe.alg}.
 *
 * <p><b>&quot;enc&quot; identifier</b></p>
 *
 * <p>{@code AeadAlgorithm} extends {@code Identifiable}: the value returned from {@link Identifiable#getId() getId()}
 * will be used as the JWE &quot;enc&quot; protected header value.</p>
 *
 * <p><b>Key Strength</b></p>
 *
 * <p>Encryption strength is in part attributed to how challenging it is to discover the encryption key.  As such,
 * cryptographic algorithms often require keys of a minimum length to ensure the keys are challenging to discover
 * and the algorithm's security properties are maintained.</p>
 *
 * <p>The {@code AeadAlgorithm} interface extends the {@link KeyLengthSupplier} interface to represent the length
 * in bits a key must have to be used with its implementation.  If you do not want to worry about lengths and
 * parameters of keys required for an algorithm, it is often easier to automatically generate a key that adheres
 * to the algorithm's requirements, as discussed below.</p>
 *
 * <p><b>Key Generation</b></p>
 *
 * <p>{@code AeadAlgorithm} extends {@link KeyBuilderSupplier} to enable {@link SecretKey} generation. Each AEAD
 * algorithm instance will return a {@link KeyBuilder} that ensures any created keys will have a sufficient length
 * and algorithm parameters required by that algorithm.  For example:</p>
 *
 * <pre><code>
 *     SecretKey key = aeadAlgorithm.key().build();
 * </code></pre>
 *
 * <p>The resulting {@code key} is guaranteed to have the correct algorithm parameters and strength/length necessary for
 * that exact {@code aeadAlgorithm} instance.</p>
 *
 * @see io.jsonwebtoken.Jwe.alg Jwe.alg
 * @see Identifiable#getId()
 * @see KeyLengthSupplier
 * @see KeyBuilderSupplier
 * @see KeyBuilder
 * @since 0.12.0
 */
public interface AeadAlgorithm extends Identifiable, KeyLengthSupplier, KeyBuilderSupplier<SecretKey, SecretKeyBuilder> {

    /**
     * Named parameters used during AEAD encryption.
     *
     * @param <P> the instance type returned for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    interface Params<P extends Params<P>> extends OctetStreamPayloadParams<P>, Keyable<SecretKey, P> {

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
     * Named parameters used during AEAD decryption.
     *
     * @param <P> the instance type returned for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    interface DecryptParams<P extends DecryptParams<P>> extends Params<P> {

        /**
         * Sets the required initialization vector used during AEAD decryption.
         *
         * @param iv the required initialization vector used during AEAD decryption.
         * @return the instance for method chaining.
         */
        P iv(byte[] iv);

        /**
         * Sets the required AEAD Authentication Tag used to verify message authenticity during AEAD decryption.
         *
         * @param digest the required AEAD Authentication Tag used to verify message authenticity during AEAD decryption.
         * @return the instance for method chaining.
         */
        P tag(byte[] digest);
    }

    /**
     * Encrypts plaintext and signs any optional {@link AeadRequest#getAssociatedData() associated data},
     * placing the resulting ciphertext, initialization vector, and authentication tag in the provided {@code result}.
     *
     * @param req the encryption request representing the plaintext to be encrypted, any additional
     *            integrity-protected data, and the encryption key.
     * @param res the result to write ciphertext, initialization vector and AAD authentication tag (aka digest)
     * @throws SecurityException if there is an encryption problem or AAD authenticity cannot be guaranteed.
     */
    void encrypt(AeadRequest req, AeadResult res) throws SecurityException;

    /**
     * Encrypts plaintext and signs any optional {@link AeadRequest#getAssociatedData() associated data} using
     * specified parameters, writing the ciphertext to the specified {@code out}put stream, and returns
     * the resulting initialization vector and authentication tag.
     * <p>
     * This is a convenience method that constructs an implicit {@link AeadResult} and {@link AeadRequest} using
     * lambda parameters, and then immediately delegates to {@link #encrypt(AeadRequest, AeadResult)}.
     * <h4>Usage Example</h4>
     * <pre><code>
     *     ByteArrayOutputStream out = new ByteArrayOutputStream(8196);
     *     AeadResult result = aeadAlgorithm.encrypt(r -&gt; r.payload(plaintext).aad(aad).key(key), out);
     *     byte[] iv = result.getIv();
     *     byte[] tag = result.getDigest();
     *     byte[] ciphertext = out.toByteArray();
     * </code></pre>
     *
     * @param p   the request parameters builder, used to set the plaintext to be encrypted, any additional data to be
     *            integrity-protected, and the encryption key necessary to encrypt the plaintext.
     * @param out the stream to receive the output ciphertext.
     * @return the result containing the initialization vector and authentication tag; the result's
     * {@link AeadResult#getOutputStream() output stream} is the same as the specified {@code out}put stream argument.
     * @throws SecurityException if there is an encryption problem or AAD authenticity cannot be guaranteed.
     * @since JJWT_RELEASE_VERSION
     */
    default AeadResult encrypt(Consumer<Params<?>> p, OutputStream out) throws SecurityException {
        Assert.notNull(p, "Consumer cannot be null");
        AeadRequest.Builder b = AeadRequest.builder();
        p.accept(b);
        AeadRequest req = b.build();
        AeadResult res = AeadResult.with(out);
        encrypt(req, res);
        return res;
    }

    /**
     * Decrypts ciphertext and authenticates any {@link DecryptAeadRequest#getAssociatedData() associated data},
     * writing the decrypted plaintext to the provided {@code out}put stream.
     *
     * @param request the decryption request representing the ciphertext to be decrypted, any additional
     *                integrity-protected data, authentication tag, initialization vector, and decryption key
     * @param out     the OutputStream to receive the decrypted plaintext
     * @throws SecurityException if there is a decryption problem or authenticity assertions fail.
     */
    void decrypt(DecryptAeadRequest request, OutputStream out) throws SecurityException;
}
