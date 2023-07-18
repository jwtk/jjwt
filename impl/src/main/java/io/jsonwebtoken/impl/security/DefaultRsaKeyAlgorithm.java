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

import io.jsonwebtoken.JweHeaderAccessor;
import io.jsonwebtoken.JweHeaderMutator;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultRsaKeyAlgorithm extends CryptoAlgorithm implements KeyAlgorithm<PublicKey, PrivateKey> {

    private final AlgorithmParameterSpec SPEC; //can be null

    private static final int MIN_KEY_BIT_LENGTH = 2048;

    public DefaultRsaKeyAlgorithm(String id, String jcaTransformationString) {
        this(id, jcaTransformationString, null);
    }

    public DefaultRsaKeyAlgorithm(String id, String jcaTransformationString, AlgorithmParameterSpec spec) {
        super(id, jcaTransformationString);
        this.SPEC = spec; //can be null
    }

    private static String keyType(boolean encryption) {
        return encryption ? "encryption" : "decryption";
    }

    protected void validate(Key key, boolean encryption) { // true = encryption, false = decryption
        // Some PKCS11 providers and HSMs won't expose the RSAKey interface, so we have to check to see if we can cast
        // If so, we can provide additional safety checks:
        if (key instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) key;
            BigInteger modulus = Assert.notNull(rsaKey.getModulus(), "RSAKey modulus cannot be null.");
            int size = modulus.bitLength();
            if (size < MIN_KEY_BIT_LENGTH) {
                String id = getId();
                String section = id.startsWith("RSA1") ? "4.2" : "4.3";
                String msg = "The RSA " + keyType(encryption) + " key's size (modulus) is " + size +
                        " bits which is not secure enough for the " + id + " algorithm. " +
                        "The JWT JWA Specification (RFC 7518, Section " + section + ") states that RSA keys MUST " +
                        "have a size >= " + MIN_KEY_BIT_LENGTH + " bits. See " +
                        "https://www.rfc-editor.org/rfc/rfc7518.html#section-" + section + " for more information.";
                throw new WeakKeyException(msg);
            }
        }
    }

    @Override
    public <H extends JweHeaderAccessor & JweHeaderMutator<H>> KeyResult getEncryptionKey(final KeyRequest<PublicKey, H> request) throws SecurityException {

        Assert.notNull(request, "Request cannot be null.");
        final PublicKey kek = Assert.notNull(request.getPayload(), "RSA PublicKey encryption key cannot be null.");
        validate(kek, true);
        final SecretKey cek = generateKey(request);

        byte[] ciphertext = jca(request).withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                if (SPEC == null) {
                    cipher.init(Cipher.WRAP_MODE, kek, ensureSecureRandom(request));
                } else {
                    cipher.init(Cipher.WRAP_MODE, kek, SPEC, ensureSecureRandom(request));
                }
                return cipher.wrap(cek);
            }
        });

        return new DefaultKeyResult(cek, ciphertext);
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<PrivateKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final PrivateKey kek = Assert.notNull(request.getKey(), "RSA PrivateKey decryption key cannot be null.");
        validate(kek, false);
        final byte[] cekBytes = Assert.notEmpty(request.getPayload(), "Request content (encrypted key) cannot be null or empty.");

        return jca(request).withCipher(new CheckedFunction<Cipher, SecretKey>() {
            @Override
            public SecretKey apply(Cipher cipher) throws Exception {
                if (SPEC == null) {
                    cipher.init(Cipher.UNWRAP_MODE, kek);
                } else {
                    cipher.init(Cipher.UNWRAP_MODE, kek, SPEC);
                }
                Key key = cipher.unwrap(cekBytes, AesAlgorithm.KEY_ALG_NAME, Cipher.SECRET_KEY);
                return Assert.isInstanceOf(SecretKey.class, key, "Cipher unwrap must return a SecretKey instance.");
            }
        });
    }
}