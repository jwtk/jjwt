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
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.IvSupplier;
import io.jsonwebtoken.security.KeyBuilderSupplier;
import io.jsonwebtoken.security.KeyLengthSupplier;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.SecretKeyBuilder;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @since 0.12.0
 */
abstract class AesAlgorithm extends CryptoAlgorithm implements KeyBuilderSupplier<SecretKey, SecretKeyBuilder>, KeyLengthSupplier {

    protected static final String KEY_ALG_NAME = "AES";
    protected static final int BLOCK_SIZE = 128;
    protected static final int BLOCK_BYTE_SIZE = BLOCK_SIZE / Byte.SIZE;
    protected static final int GCM_IV_SIZE = 96; // https://tools.ietf.org/html/rfc7518#section-5.3
    //protected static final int GCM_IV_BYTE_SIZE = GCM_IV_SIZE / Byte.SIZE;
    protected static final String DECRYPT_NO_IV = "This algorithm implementation rejects decryption " +
            "requests that do not include initialization vectors. AES ciphertext without an IV is weak and " +
            "susceptible to attack.";

    protected final int keyBitLength;
    protected final int ivBitLength;
    protected final int tagBitLength;
    protected final boolean gcm;

    /**
     * Ensures {@code keyBitLength is a valid AES key length}
     * @param keyBitLength the key length (in bits) to check
     * @since 0.12.4
     */
    static void assertKeyBitLength(int keyBitLength) {
        if (keyBitLength == 128 || keyBitLength == 192 || keyBitLength == 256) return; // valid
        String msg = "Invalid AES key length: " + Bytes.bitsMsg(keyBitLength) + ". AES only supports " +
                "128, 192, or 256 bit keys.";
        throw new IllegalArgumentException(msg);
    }

    static SecretKey keyFor(byte[] bytes) {
        int bitlen = (int) Bytes.bitLength(bytes);
        assertKeyBitLength(bitlen);
        return new SecretKeySpec(bytes, KEY_ALG_NAME);
    }

    AesAlgorithm(String id, final String jcaTransformation, int keyBitLength) {
        super(id, jcaTransformation);
        assertKeyBitLength(keyBitLength);
        this.keyBitLength = keyBitLength;
        this.gcm = jcaTransformation.startsWith("AES/GCM");
        this.ivBitLength = jcaTransformation.equals("AESWrap") ? 0 : (this.gcm ? GCM_IV_SIZE : BLOCK_SIZE);
        // https://tools.ietf.org/html/rfc7518#section-5.2.3 through https://tools.ietf.org/html/rfc7518#section-5.3 :
        this.tagBitLength = this.gcm ? BLOCK_SIZE : this.keyBitLength;
    }

    @Override
    public int getKeyBitLength() {
        return this.keyBitLength;
    }

    @Override
    public SecretKeyBuilder key() {
        return new DefaultSecretKeyBuilder(KEY_ALG_NAME, getKeyBitLength());
    }

    protected SecretKey assertKey(SecretKey key) {
        Assert.notNull(key, "Request key cannot be null.");
        validateLengthIfPossible(key);
        return key;
    }

    private void validateLengthIfPossible(SecretKey key) {
        validateLength(key, this.keyBitLength, false);
    }

    protected static String lengthMsg(String id, String type, int requiredLengthInBits, long actualLengthInBits) {
        return "The '" + id + "' algorithm requires " + type + " with a length of " +
                Bytes.bitsMsg(requiredLengthInBits) + ".  The provided key has a length of " +
                Bytes.bitsMsg(actualLengthInBits) + ".";
    }

    protected byte[] validateLength(SecretKey key, int requiredBitLength, boolean propagate) {
        byte[] keyBytes;

        try {
            keyBytes = key.getEncoded();
        } catch (RuntimeException re) {
            if (propagate) {
                throw re;
            }
            //can't get the bytes to validate, e.g. hardware security module or later Android, so just return:
            return null;
        }
        long keyBitLength = Bytes.bitLength(keyBytes);
        if (keyBitLength < requiredBitLength) {
            throw new WeakKeyException(lengthMsg(getId(), "keys", requiredBitLength, keyBitLength));
        }

        return keyBytes;
    }

    protected byte[] assertBytes(byte[] bytes, String type, int requiredBitLen) {
        long bitLen = Bytes.bitLength(bytes);
        if (requiredBitLen != bitLen) {
            String msg = lengthMsg(getId(), type, requiredBitLen, bitLen);
            throw new IllegalArgumentException(msg);
        }
        return bytes;
    }

    byte[] assertIvLength(final byte[] iv) {
        return assertBytes(iv, "initialization vectors", this.ivBitLength);
    }

    byte[] assertTag(byte[] tag) {
        return assertBytes(tag, "authentication tags", this.tagBitLength);
    }

    byte[] assertDecryptionIv(IvSupplier src) throws IllegalArgumentException {
        byte[] iv = src.getIv();
        Assert.notEmpty(iv, DECRYPT_NO_IV);
        return assertIvLength(iv);
    }

    protected byte[] ensureInitializationVector(Request<?> request) {
        byte[] iv = null;
        if (request instanceof IvSupplier) {
            iv = Arrays.clean(((IvSupplier) request).getIv());
        }
        int ivByteLength = this.ivBitLength / Byte.SIZE;
        if (iv == null || iv.length == 0) {
            iv = new byte[ivByteLength];
            SecureRandom random = ensureSecureRandom(request);
            random.nextBytes(iv);
        } else {
            assertIvLength(iv);
        }
        return iv;
    }

    protected AlgorithmParameterSpec getIvSpec(byte[] iv) {
        Assert.notEmpty(iv, "Initialization Vector byte array cannot be null or empty.");
        return this.gcm ? new GCMParameterSpec(BLOCK_SIZE, iv) : new IvParameterSpec(iv);
    }

    protected void withCipher(Cipher cipher, InputStream in, OutputStream out) throws Exception {
        byte[] last = withCipher(cipher, in, null, out);
        out.write(last); // no AAD, so no tag, so we can just append
    }

    private void updateAAD(Cipher cipher, InputStream aad) throws Exception {
        if (aad == null) return;
        byte[] buf = new byte[2048];
        int len = 0;
        while (len != -1) {
            len = aad.read(buf);
            if (len > 0) {
                cipher.updateAAD(buf, 0, len);
            }
        }
    }

    protected byte[] withCipher(Cipher cipher, InputStream in, InputStream aad, OutputStream out) throws Exception {
        updateAAD(cipher, aad); // no-op if aad is null
        byte[] buf = new byte[2048];
        try {
            int len = 0;
            while (len != -1) {
                len = in.read(buf);
                if (len > 0) {
                    byte[] enc = cipher.update(buf, 0, len);
                    Streams.write(out, enc, "Unable to write Cipher output to OutputStream");
                }
            }
            return cipher.doFinal();
        } finally {
            Bytes.clear(buf);
        }
    }
}
