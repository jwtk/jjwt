package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadIvRequest;
import io.jsonwebtoken.security.AeadIvEncryptionResult;
import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.AeadSymmetricEncryptionAlgorithm;
import io.jsonwebtoken.security.AssociatedDataSource;
import io.jsonwebtoken.security.CryptoException;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.InitializationVectorSource;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

import static io.jsonwebtoken.lang.Arrays.*;

/**
 * @since JJWT_RELEASE_VERSION
 */
abstract class AbstractAeadAesEncryptionAlgorithm
    extends AbstractEncryptionAlgorithm<byte[], SecretKey, SecretKey, AeadRequest<byte[], SecretKey>, AeadIvEncryptionResult, AeadIvRequest<byte[], SecretKey>>
    implements AeadSymmetricEncryptionAlgorithm<byte[]> {

    protected static final int AES_BLOCK_SIZE_BYTES = 16;
    protected static final int AES_BLOCK_SIZE_BITS = AES_BLOCK_SIZE_BYTES * Byte.SIZE;
    public static final String INVALID_GENERATED_IV_LENGTH =
            "generatedIvLengthInBits must be a positive number <= " + AES_BLOCK_SIZE_BITS;

    protected static final String DECRYPT_NO_IV = "This EncryptionAlgorithm implementation rejects decryption " +
            "requests that do not include initialization vectors.  AES ciphertext without an IV is weak and should " +
            "never be used.";

    private final int generatedIvByteLength;
    private final int requiredKeyByteLength;
    private final int requiredKeyBitLength;

    public AbstractAeadAesEncryptionAlgorithm(String name, String transformationString, int generatedIvLengthInBits, int requiredKeySizeInBits) {

        super(name, transformationString);

        Assert.isTrue(generatedIvLengthInBits > 0 && generatedIvLengthInBits <= AES_BLOCK_SIZE_BITS, INVALID_GENERATED_IV_LENGTH);
        Assert.isTrue((generatedIvLengthInBits % Byte.SIZE) == 0, "generatedIvLengthInBits must be evenly divisible by 8.");
        this.generatedIvByteLength = generatedIvLengthInBits / Byte.SIZE;

        Assert.isTrue(requiredKeySizeInBits > 0, "requiredKeyLengthInBits must be greater than zero.");
        Assert.isTrue((requiredKeySizeInBits % Byte.SIZE) == 0, "requiredKeyLengthInBits must be evenly divisible by 8.");
        this.requiredKeyBitLength = requiredKeySizeInBits;
        this.requiredKeyByteLength = requiredKeySizeInBits / Byte.SIZE;
    }

    public int getRequiredKeyByteLength() {
        return this.requiredKeyByteLength;
    }

    @Override
    public SecretKey generateKey() {
        try {
            return doGenerateKey();
        } catch (Exception e) {
            throw new CryptoException("Unable to generate a new " + getName() + " SecretKey: " + e.getMessage(), e);
        }
    }

    protected SecretKey doGenerateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(this.requiredKeyBitLength);
        return keyGenerator.generateKey();
    }

    byte[] ensureInitializationVector(AeadRequest request) {
        byte[] iv = null;
        if (request instanceof InitializationVectorSource) {
            iv = Arrays.clean(((InitializationVectorSource)request).getInitializationVector());
        }
        if (Arrays.length(iv) == 0) {
            iv = new byte[this.generatedIvByteLength];
            SecureRandom random = ensureSecureRandom(request);
            random.nextBytes(iv);
        }
        return iv;
    }

    SecretKey assertKey(CryptoRequest<?, SecretKey> request) {
        SecretKey key = request.getKey();
        return assertKeyLength(key);
    }

    SecretKey assertKeyLength(SecretKey key) {
        int length = length(key.getEncoded());
        if (length != requiredKeyByteLength) {
            throw new CryptoException("The " + getName() + " algorithm requires that keys have a key length of " +
                    "(preferably secure-random) " + requiredKeyBitLength + " bits (" +
                requiredKeyByteLength + " bytes). The provided key has a length of " + length * Byte.SIZE
                    + " bits (" + length + " bytes).");
        }
        return key;
    }

    byte[] assertDecryptionIv(InitializationVectorSource src) throws IllegalArgumentException {
        byte[] iv = src.getInitializationVector();
        Assert.notEmpty(iv, DECRYPT_NO_IV);
        return iv;
    }

    byte[] getAAD(AssociatedDataSource src) {
        byte[] aad = src.getAssociatedData();
        return io.jsonwebtoken.lang.Arrays.clean(aad);
    }
}
