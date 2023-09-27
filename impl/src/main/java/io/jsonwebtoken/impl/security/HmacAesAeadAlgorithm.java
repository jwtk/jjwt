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
import io.jsonwebtoken.security.Message;
import io.jsonwebtoken.security.SecretKeyBuilder;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class HmacAesAeadAlgorithm extends AesAlgorithm implements AeadAlgorithm {

    private static final String TRANSFORMATION_STRING = "AES/CBC/PKCS5Padding";

    private final DefaultMacAlgorithm SIGALG;

    private static int digestLength(int keyLength) {
        return keyLength * 2;
    }

    private static String id(int keyLength) {
        return "A" + keyLength + "CBC-HS" + digestLength(keyLength);
    }

    public HmacAesAeadAlgorithm(String id, DefaultMacAlgorithm sigAlg) {
        super(id, TRANSFORMATION_STRING, sigAlg.getKeyBitLength());
        this.SIGALG = sigAlg;
    }

    public HmacAesAeadAlgorithm(int keyBitLength) {
        this(id(keyBitLength), new DefaultMacAlgorithm(id(keyBitLength), "HmacSHA" + digestLength(keyBitLength), keyBitLength));
    }

    @Override
    public int getKeyBitLength() {
        return super.getKeyBitLength() * 2;
    }

    @Override
    public SecretKeyBuilder key() {
        // The Sun JCE KeyGenerator throws an exception if bitLengths are not standard AES 128, 192 or 256 values.
        // Since the JWA HmacAes algorithms require double that, we use secure-random keys instead:
        return new RandomSecretKeyBuilder(KEY_ALG_NAME, getKeyBitLength());
    }

    byte[] assertKeyBytes(SecureRequest<?, SecretKey> request) {
        SecretKey key = Assert.notNull(request.getKey(), "Request key cannot be null.");
        return validateLength(key, this.keyBitLength * 2, true);
    }

    @Override
    public AeadResult encrypt(final AeadRequest req) {

        Assert.notNull(req, "Request cannot be null.");

        byte[] compositeKeyBytes = assertKeyBytes(req);
        int halfCount = compositeKeyBytes.length / 2; // https://tools.ietf.org/html/rfc7518#section-5.2
        byte[] macKeyBytes = Arrays.copyOfRange(compositeKeyBytes, 0, halfCount);
        byte[] encKeyBytes = Arrays.copyOfRange(compositeKeyBytes, halfCount, compositeKeyBytes.length);
        final SecretKey encryptionKey = new SecretKeySpec(encKeyBytes, KEY_ALG_NAME);

        final InputStream plaintext = Assert.notNull(req.getPayload(),
                "Request content (plaintext) InputStream cannot be null or empty.");
        final byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty
        final byte[] iv = ensureInitializationVector(req);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        final ByteArrayOutputStream out = new ByteArrayOutputStream();

        jca(req).withCipher(new CheckedFunction<Cipher, Object>() {
            @Override
            public Object apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivSpec);
                withCipher(cipher, plaintext, out);
                return null; // don't need to return anything
            }
        });

        byte[] ciphertext = out.toByteArray();
        byte[] tag = sign(aad, iv, ciphertext, macKeyBytes);

        InputStream stream = new ByteArrayInputStream(ciphertext);
        return new DefaultAeadResult(req.getProvider(), req.getSecureRandom(), stream, encryptionKey, aad, tag, iv);
    }

    private byte[] sign(byte[] aad, byte[] iv, byte[] ciphertext, byte[] macKeyBytes) {

        long aadLength = io.jsonwebtoken.lang.Arrays.length(aad);
        long aadLengthInBits = aadLength * Byte.SIZE;
        long aadLengthInBitsAsUnsignedInt = aadLengthInBits & 0xffffffffL;
        byte[] AL = Bytes.toBytes(aadLengthInBitsAsUnsignedInt);

        Collection<InputStream> streams = new ArrayList<>(4);
        if (!Bytes.isEmpty(aad)) { // must come first if it exists
            streams.add(new ByteArrayInputStream(aad));
        }
        streams.add(new ByteArrayInputStream(iv));
        streams.add(new ByteArrayInputStream(ciphertext));
        streams.add(new ByteArrayInputStream(AL));
        InputStream in = new SequenceInputStream(Collections.enumeration(streams));

        SecretKey key = new SecretKeySpec(macKeyBytes, SIGALG.getJcaName());
        SecureRequest<InputStream, SecretKey> request =
                new DefaultSecureRequest<>(in, null, null, key);
        byte[] digest = SIGALG.digest(request);

        // https://tools.ietf.org/html/rfc7518#section-5.2.2.1 #5 requires truncating the signature
        // to be the same length as the macKey/encKey:
        return assertTag(Arrays.copyOfRange(digest, 0, macKeyBytes.length));
    }

    @Override
    public Message<byte[]> decrypt(final DecryptAeadRequest req) {

        Assert.notNull(req, "Request cannot be null.");

        byte[] compositeKeyBytes = assertKeyBytes(req);
        int halfCount = compositeKeyBytes.length / 2; // https://tools.ietf.org/html/rfc7518#section-5.2
        byte[] macKeyBytes = Arrays.copyOfRange(compositeKeyBytes, 0, halfCount);
        byte[] encKeyBytes = Arrays.copyOfRange(compositeKeyBytes, halfCount, compositeKeyBytes.length);
        final SecretKey decryptionKey = new SecretKeySpec(encKeyBytes, KEY_ALG_NAME);

        final byte[] ciphertext = Assert.notEmpty(Streams.bytes(req.getPayload(), "testing"), "Decryption request content (ciphertext) cannot be null or empty.");
        final byte[] aad = getAAD(req);
        final byte[] tag = assertTag(req.getDigest());
        final byte[] iv = assertDecryptionIv(req);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        // Assert that the aad + iv + ciphertext provided, when signed, equals the tag provided,
        // thereby verifying none of it has been tampered with:
        byte[] digest = sign(aad, iv, ciphertext, macKeyBytes);
        if (!MessageDigest.isEqual(digest, tag)) { //constant time comparison to avoid side-channel attacks
            String msg = "Ciphertext decryption failed: Authentication tag verification failed.";
            throw new SignatureException(msg);
        }

        byte[] plaintext = jca(req).withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
                return cipher.doFinal(ciphertext);
            }
        });

        return new DefaultMessage<>(plaintext);
    }
}
