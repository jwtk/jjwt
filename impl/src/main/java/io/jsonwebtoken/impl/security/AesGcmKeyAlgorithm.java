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

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.impl.DefaultJweHeader;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.RequiredParameterReader;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecretKeyAlgorithm;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class AesGcmKeyAlgorithm extends AesAlgorithm implements SecretKeyAlgorithm {

    public static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public AesGcmKeyAlgorithm(int keyLen) {
        super("A" + keyLen + "GCMKW", TRANSFORMATION, keyLen);
    }

    @Override
    public KeyResult getEncryptionKey(final KeyRequest<SecretKey> request) throws SecurityException {

        Assert.notNull(request, "request cannot be null.");
        final JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        final SecretKey kek = assertKey(request.getPayload());
        final SecretKey cek = generateCek(request);
        final byte[] iv = ensureInitializationVector(request);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        byte[] taggedCiphertext = jca(request).withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek, ivSpec);
                return cipher.wrap(cek);
            }
        });

        int tagByteLength = this.tagBitLength / Byte.SIZE;
        // When using GCM mode, the JDK appends the authentication tag to the ciphertext, so let's extract it:
        int ciphertextLength = taggedCiphertext.length - tagByteLength;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(taggedCiphertext, 0, ciphertext, 0, ciphertextLength);
        byte[] tag = new byte[tagByteLength];
        System.arraycopy(taggedCiphertext, ciphertextLength, tag, 0, tagByteLength);

        String encodedIv = Encoders.BASE64URL.encode(iv);
        String encodedTag = Encoders.BASE64URL.encode(tag);
        header.put(DefaultJweHeader.IV.getId(), encodedIv);
        header.put(DefaultJweHeader.TAG.getId(), encodedTag);

        return new DefaultKeyResult(cek, ciphertext);
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request.getKey());
        final byte[] cekBytes = Assert.notEmpty(request.getPayload(), "Decryption request content (ciphertext) cannot be null or empty.");
        final JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        ParameterReadable frHeader = Assert.isInstanceOf(ParameterReadable.class, header, "Header must implement ParameterReadable.");
        final ParameterReadable reader = new RequiredParameterReader(frHeader);
        final byte[] tag = reader.get(DefaultJweHeader.TAG);
        final byte[] iv = reader.get(DefaultJweHeader.IV);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        //for tagged GCM, the JCA spec requires that the tag be appended to the end of the ciphertext byte array:
        final byte[] taggedCiphertext = Bytes.concat(cekBytes, tag);

        return jca(request).withCipher(new CheckedFunction<Cipher, SecretKey>() {
            @Override
            public SecretKey apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.UNWRAP_MODE, kek, ivSpec);
                Key key = cipher.unwrap(taggedCiphertext, KEY_ALG_NAME, Cipher.SECRET_KEY);
                Assert.state(key instanceof SecretKey, "cipher.unwrap must produce a SecretKey instance.");
                return (SecretKey) key;
            }
        });
    }
}
