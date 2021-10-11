package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AssociatedDataSupplier;
import io.jsonwebtoken.security.InitializationVectorSupplier;
import io.jsonwebtoken.security.KeySupplier;
import io.jsonwebtoken.security.SecretKeyGenerator;
import io.jsonwebtoken.security.SecurityRequest;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static io.jsonwebtoken.lang.Arrays.*;


abstract class AesAlgorithm extends CryptoAlgorithm implements SecretKeyGenerator {

    protected static final String KEY_ALG_NAME = "AES";
    protected static final int BLOCK_SIZE = 128;
    protected static final int BLOCK_BYTE_SIZE = BLOCK_SIZE / Byte.SIZE;
    protected static final int GCM_IV_SIZE = 96; // https://tools.ietf.org/html/rfc7518#section-5.3
    protected static final int GCM_IV_BYTE_SIZE = GCM_IV_SIZE / Byte.SIZE;
    protected static final String DECRYPT_NO_IV = "This algorithm implementation rejects decryption " +
        "requests that do not include initialization vectors. AES ciphertext without an IV is weak and " +
        "susceptible to attack.";

    protected final int keyBitLength;
    protected final int ivBitLength;
    protected final int tagBitLength;
    protected final boolean gcm;

    AesAlgorithm(String id, String jcaTransformation, int keyBitLength) {
        super(id, jcaTransformation);
        Assert.isTrue(keyBitLength == 128 || keyBitLength == 192 || keyBitLength == 256, "Invalid AES key length: it must equal 128, 192, or 256.");
        this.keyBitLength = keyBitLength;
        this.gcm = jcaTransformation.startsWith("AES/GCM");
        this.ivBitLength = jcaTransformation.equals("AESWrap") ? 0 : (this.gcm ? GCM_IV_SIZE : BLOCK_SIZE);
        // https://tools.ietf.org/html/rfc7518#section-5.2.3 through https://tools.ietf.org/html/rfc7518#section-5.3 :
        this.tagBitLength = this.gcm ? BLOCK_SIZE : this.keyBitLength;
    }

    @Override
    public SecretKey generateKey() {
        return new JcaTemplate(KEY_ALG_NAME, null).generateSecretKey(this.keyBitLength);
        //TODO: assert generated key length?
    }

    protected SecretKey assertKey(KeySupplier<? extends SecretKey> request) {
        SecretKey key = Assert.notNull(request.getKey(), "Request key cannot be null.");
        validateLengthIfPossible(key);
        return key;
    }

    private void validateLengthIfPossible(SecretKey key) {
        validateLength(key, this.keyBitLength, false);
    }

    protected static String lengthMsg(String id, String type, int requiredLengthInBits, int actualLengthInBits) {
        return "The '" + id + "' algorithm requires " + type + " with a length of " +
            Bytes.bitsMsg(requiredLengthInBits) + ".  The provided key has a length of " +
            Bytes.bitsMsg(actualLengthInBits) + ".";
    }

    protected byte[] validateLength(SecretKey key, int requiredBitLength, boolean propagate) {
        byte[] keyBytes = null;

        try {
            keyBytes = key.getEncoded();
        } catch (RuntimeException re) {
            if (propagate) {
                throw re;
            }
            //can't get the bytes to validate, e.g. hardware security module or later Android, so just return:
            return keyBytes;
        }
        int keyBitLength = keyBytes.length * Byte.SIZE;
        if (keyBitLength < requiredBitLength) {
            throw new WeakKeyException(lengthMsg(getId(), "keys", requiredBitLength, keyBitLength));
        }

        return keyBytes;
    }

    byte[] assertIvLength(final byte[] iv) {
        int length = length(iv);
        if ((this.ivBitLength / Byte.SIZE) != length) {
            String msg = lengthMsg(getId(), "initialization vectors", this.ivBitLength, length * Byte.SIZE);
            throw new IllegalArgumentException(msg);
        }
        return iv;
    }

    byte[] assertTag(byte[] tag) {
        int len = Arrays.length(tag) * Byte.SIZE;
        if (this.tagBitLength != len) {
            String msg = lengthMsg(getId(), "authentication tags", this.tagBitLength, len);
            throw new IllegalArgumentException(msg);
        }
        return tag;
    }

    byte[] assertDecryptionIv(InitializationVectorSupplier src) throws IllegalArgumentException {
        byte[] iv = src.getInitializationVector();
        Assert.notEmpty(iv, DECRYPT_NO_IV);
        return assertIvLength(iv);
    }

    protected byte[] ensureInitializationVector(SecurityRequest request) {
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
        if (Arrays.length(iv) == 0) {
            return null;
        }
        return this.gcm ? new GCMParameterSpec(BLOCK_SIZE, iv) : new IvParameterSpec(iv);
    }

    protected byte[] getAAD(SecurityRequest request) {
        byte[] aad = null;
        if (request instanceof AssociatedDataSupplier) {
            aad = Arrays.clean(((AssociatedDataSupplier) request).getAssociatedData());
        }
        return aad;
    }
}
