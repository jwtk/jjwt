package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.PayloadSupplier;
import io.jsonwebtoken.security.SymmetricAeadAlgorithm;
import io.jsonwebtoken.security.AssociatedDataSource;
import io.jsonwebtoken.security.CryptoException;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.InitializationVectorSource;
import io.jsonwebtoken.security.SymmetricAeadDecryptionRequest;
import io.jsonwebtoken.security.SymmetricAeadEncryptionResult;
import io.jsonwebtoken.security.SymmetricAeadRequest;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

import static io.jsonwebtoken.lang.Arrays.*;

/**
 * @since JJWT_RELEASE_VERSION
 */
abstract class AesAeadAlgorithm
    extends AbstractEncryptionAlgorithm<byte[], SecretKey, SecretKey, SymmetricAeadRequest, SymmetricAeadEncryptionResult, SymmetricAeadDecryptionRequest, PayloadSupplier<byte[]>>
    implements SymmetricAeadAlgorithm {

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

    public AesAeadAlgorithm(String id, String transformationString, int generatedIvLengthInBits, int requiredKeyLengthInBits) {

        super(id, transformationString);

        Assert.isTrue(generatedIvLengthInBits > 0 && generatedIvLengthInBits <= AES_BLOCK_SIZE_BITS, INVALID_GENERATED_IV_LENGTH);
        Assert.isTrue((generatedIvLengthInBits % Byte.SIZE) == 0, "generatedIvLengthInBits must be evenly divisible by 8.");
        this.generatedIvByteLength = generatedIvLengthInBits / Byte.SIZE;

        Assert.isTrue(requiredKeyLengthInBits > 0, "requiredKeyLengthInBits must be greater than zero.");
        Assert.isTrue((requiredKeyLengthInBits % Byte.SIZE) == 0, "requiredKeyLengthInBits must be evenly divisible by 8.");
        this.requiredKeyBitLength = requiredKeyLengthInBits;
        this.requiredKeyByteLength = requiredKeyLengthInBits / Byte.SIZE;
    }

    public int getRequiredKeyByteLength() {
        return this.requiredKeyByteLength;
    }

    @Override
    public SecretKey generateKey() {
        return new JcaTemplate("AES", null).generateSecretKey(requiredKeyBitLength);
        //TODO: assert generated key length?
    }

    byte[] ensureInitializationVector(CryptoRequest<?,?> request) {
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
            throw new CryptoException("The " + getId() + " algorithm requires that keys have a key length of " +
                    "(preferably secure-random) " + requiredKeyBitLength + " bits (" +
                requiredKeyByteLength + " bytes). The provided key has a length of " + length * Byte.SIZE
                    + " bits (" + length + " bytes).");
        }
        return key;
    }

    byte[] assertIvLength(final byte[] iv) {
        int length = length(iv);
        if (length != generatedIvByteLength) {
            String msg = "The " + getId() + " algorithm requires initialization vectors with a " +
                "length of " + generatedIvByteLength * Byte.SIZE + " bits (" + generatedIvByteLength + " bytes).  " +
                "The provided initialization vector has a length of " + length * Byte.SIZE + " bits (" +
                length + " bytes).";
            throw new CryptoException(msg);
        }
        return iv;
    }

    byte[] assertDecryptionIv(InitializationVectorSource src) throws IllegalArgumentException {
        byte[] iv = src.getInitializationVector();
        Assert.notEmpty(iv, DECRYPT_NO_IV);
        return assertIvLength(iv);
    }

    byte[] getAAD(AssociatedDataSource src) {
        byte[] aad = src.getAssociatedData();
        return io.jsonwebtoken.lang.Arrays.clean(aad);
    }
}
