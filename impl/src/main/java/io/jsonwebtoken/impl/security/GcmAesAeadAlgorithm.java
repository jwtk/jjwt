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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.io.Streams;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.AeadResult;
import io.jsonwebtoken.security.DecryptAeadRequest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @since 0.12.0
 */
public class GcmAesAeadAlgorithm extends AesAlgorithm implements AeadAlgorithm {

    private static final String TRANSFORMATION_STRING = "AES/GCM/NoPadding";

    public GcmAesAeadAlgorithm(int keyLength) {
        super("A" + keyLength + "GCM", TRANSFORMATION_STRING, keyLength);
    }

    @Override
    public void encrypt(final AeadRequest req, AeadResult res) throws SecurityException {

        Assert.notNull(req, "Request cannot be null.");
        Assert.notNull(res, "Result cannot be null.");

        final SecretKey key = assertKey(req.getKey());
        final InputStream plaintext = Assert.notNull(req.getPayload(),
                "Request content (plaintext) InputStream cannot be null.");
        final OutputStream out = Assert.notNull(res.getOutputStream(),
                "Result ciphertext OutputStream cannot be null.");
        final InputStream aad = req.getAssociatedData();
        final byte[] iv = ensureInitializationVector(req);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        final byte[] tag = jca(req).withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                byte[] taggedCiphertext = withCipher(cipher, plaintext, aad, out);
                // When using GCM mode, the JDK appends the authentication tag to the ciphertext, so let's extract it:
                // (tag has a length of BLOCK_BYTE_SIZE):
                int ciphertextLength = Bytes.length(taggedCiphertext) - BLOCK_BYTE_SIZE;
                Streams.write(out, taggedCiphertext, 0, ciphertextLength, "Ciphertext write failure.");
                byte[] tag = new byte[BLOCK_BYTE_SIZE];
                System.arraycopy(taggedCiphertext, ciphertextLength, tag, 0, BLOCK_BYTE_SIZE);
                return tag;
            }
        });
        Streams.flush(out);
        Streams.reset(plaintext);

        res.setTag(tag).setIv(iv);
    }

    @Override
    public void decrypt(final DecryptAeadRequest req, final OutputStream out) throws SecurityException {

        Assert.notNull(req, "Request cannot be null.");
        Assert.notNull(out, "Plaintext OutputStream cannot be null.");
        final SecretKey key = assertKey(req.getKey());
        final InputStream ciphertext = Assert.notNull(req.getPayload(),
                "Decryption request content (ciphertext) InputStream cannot be null.");
        final InputStream aad = req.getAssociatedData();
        final byte[] tag = Assert.notEmpty(req.getDigest(),
                "Decryption request authentication tag cannot be null or empty.");
        final byte[] iv = assertDecryptionIv(req);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        //for tagged GCM, the JCA spec requires that the tag be appended to the end of the ciphertext byte array:
        final InputStream taggedCiphertext = new SequenceInputStream(ciphertext, Streams.of(tag));

        jca(req).withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                byte[] last = withCipher(cipher, taggedCiphertext, aad, out);
                Streams.write(out, last, "GcmAesAeadAlgorithm#decrypt plaintext write failure.");
                return Bytes.EMPTY;
            }
        });
        Streams.flush(out);
    }
}
