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

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecretKeyAlgorithm;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class AesWrapKeyAlgorithm extends AesAlgorithm implements SecretKeyAlgorithm {

    private static final String TRANSFORMATION = "AESWrap";

    public AesWrapKeyAlgorithm(int keyLen) {
        super("A" + keyLen + "KW", TRANSFORMATION, keyLen);
    }

    @Override
    public KeyResult getEncryptionKey(final KeyRequest<SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request.getPayload());
        final SecretKey cek = generateCek(request);

        byte[] ciphertext = jca(request).withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek);
                return cipher.wrap(cek);
            }
        });

        return new DefaultKeyResult(cek, ciphertext);
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request.getKey());
        final byte[] cekBytes = Assert.notEmpty(request.getPayload(), "Request content (encrypted key) cannot be null or empty.");

        return jca(request).withCipher(new CheckedFunction<Cipher, SecretKey>() {
            @Override
            public SecretKey apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.UNWRAP_MODE, kek);
                Key key = cipher.unwrap(cekBytes, KEY_ALG_NAME, Cipher.SECRET_KEY);
                Assert.state(key instanceof SecretKey, "Cipher unwrap must return a SecretKey instance.");
                return (SecretKey) key;
            }
        });
    }
}
