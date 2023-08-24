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
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AssociatedDataSupplier;
import io.jsonwebtoken.security.InitializationVectorSupplier;
import io.jsonwebtoken.security.KeyBuilderSupplier;
import io.jsonwebtoken.security.KeyLengthSupplier;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.SecretKeyBuilder;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
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

    AesAlgorithm(String id, final String jcaTransformation, int keyBitLength) {
        super(id, jcaTransformation);
        Assert.isTrue(keyBitLength == 128 || keyBitLength == 192 || keyBitLength == 256, "Invalid AES key length: it must equal 128, 192, or 256.");
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

    byte[] assertDecryptionIv(InitializationVectorSupplier src) throws IllegalArgumentException {
        byte[] iv = src.getInitializationVector();
        Assert.notEmpty(iv, DECRYPT_NO_IV);
        return assertIvLength(iv);
    }

    protected byte[] ensureInitializationVector(Request<?> request) {
        byte[] iv = null;
        if (request instanceof InitializationVectorSupplier) {
            iv = Arrays.clean(((InitializationVectorSupplier) request).getInitializationVector());
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

    protected byte[] getAAD(AssociatedDataSupplier request) {
        return Arrays.clean(request.getAssociatedData());
    }
}
