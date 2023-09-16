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

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.AeadResult;
import io.jsonwebtoken.security.DecryptAeadRequest;
import io.jsonwebtoken.security.Message;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class GcmAesAeadAlgorithm extends AesAlgorithm implements AeadAlgorithm {

    private static final String TRANSFORMATION_STRING = "AES/GCM/NoPadding";

    public GcmAesAeadAlgorithm(int keyLength) {
        super("A" + keyLength + "GCM", TRANSFORMATION_STRING, keyLength);
    }

    @Override
    public AeadResult encrypt(final AeadRequest req) throws SecurityException {

        Assert.notNull(req, "Request cannot be null.");
        final SecretKey key = assertKey(req.getKey());
        final byte[] plaintext = Assert.notEmpty(req.getPayload(), "Request content (plaintext) cannot be null or empty.");
        final byte[] aad = getAAD(req);
        final byte[] iv = ensureInitializationVector(req);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        byte[] taggedCiphertext = jca(req).withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                if (Arrays.length(aad) > 0) {
                    cipher.updateAAD(aad);
                }
                return cipher.doFinal(plaintext);
            }
        });

        // When using GCM mode, the JDK appends the authentication tag to the ciphertext, so let's extract it:
        // (tag has a length of BLOCK_SIZE_BITS):
        int ciphertextLength = taggedCiphertext.length - BLOCK_BYTE_SIZE;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(taggedCiphertext, 0, ciphertext, 0, ciphertextLength);
        byte[] tag = new byte[BLOCK_BYTE_SIZE];
        System.arraycopy(taggedCiphertext, ciphertextLength, tag, 0, BLOCK_BYTE_SIZE);

        return new DefaultAeadResult(req.getProvider(), req.getSecureRandom(), ciphertext, key, aad, tag, iv);
    }

    @Override
    public Message<byte[]> decrypt(final DecryptAeadRequest req) throws SecurityException {

        Assert.notNull(req, "Request cannot be null.");
        final SecretKey key = assertKey(req.getKey());
        final byte[] ciphertext = Assert.notEmpty(req.getPayload(), "Decryption request content (ciphertext) cannot be null or empty.");
        final byte[] aad = getAAD(req);
        final byte[] tag = Assert.notEmpty(req.getDigest(), "Decryption request authentication tag cannot be null or empty.");
        final byte[] iv = assertDecryptionIv(req);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        //for tagged GCM, the JCA spec requires that the tag be appended to the end of the ciphertext byte array:
        final byte[] taggedCiphertext = Bytes.concat(ciphertext, tag);

        byte[] plaintext = jca(req).withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                if (Arrays.length(aad) > 0) {
                    cipher.updateAAD(aad);
                }
                return cipher.doFinal(taggedCiphertext);
            }
        });

        return new DefaultMessage<>(plaintext);
    }
}
