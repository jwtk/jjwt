package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.lang.Assert;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static io.jsonwebtoken.lang.Arrays.length;

public abstract class AbstractAesEncryptionAlgorithm implements EncryptionAlgorithm {

    public static final SecureRandom DEFAULT_RANDOM = new SecureRandom();

    protected static final int AES_BLOCK_SIZE = 16;
    public static final String INVALID_GENERATED_IV_LENGTH =
            "generatedIvLength must be a positive number <= " + AES_BLOCK_SIZE;

    protected static final String DECRYPT_NO_IV = "This EncryptionAlgorithm implementation rejects decryption " +
            "requests that do not include initialization values.  AES ciphertext without an IV is weak and should " +
            "never be used.";

    private final String name;
    private final String transformationString;
    private final int generatedIvLength;
    private final int requiredKeyLength;

    public AbstractAesEncryptionAlgorithm(String name, String transformationString, int generatedIvLength, int requiredKeyLength) {

        Assert.hasText(name, "Name cannot be null or empty.");
        this.name = name;

        this.transformationString = transformationString;

        Assert.isTrue(generatedIvLength > 0 && generatedIvLength <= AES_BLOCK_SIZE, INVALID_GENERATED_IV_LENGTH);
        this.generatedIvLength = generatedIvLength;

        Assert.isTrue(requiredKeyLength > 0, "requiredKeyLength must be greater than zero.");
        this.requiredKeyLength = requiredKeyLength;
    }

    public int getRequiredKeyLength() {
        return this.requiredKeyLength;
    }

    public SecretKey generateKey() {
        try {
            return doGenerateKey();
        } catch (Exception e) {
            throw new CryptoException("Unable to generate a new " + getName() + " SecretKey: " + e.getMessage(), e);
        }
    }

    protected SecretKey doGenerateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int generatedKeyLength = getRequiredKeyLength();
        keyGenerator.init(generatedKeyLength * Byte.SIZE);
        return keyGenerator.generateKey();
    }

    @Override
    public String getName() {
        return this.name;
    }

    protected Cipher createCipher(int mode, Key key, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(this.transformationString);

        AlgorithmParameterSpec spec = createAlgorithmParameterSpec(iv);

        cipher.init(mode, key, spec);

        return cipher;
    }

    protected AlgorithmParameterSpec createAlgorithmParameterSpec(byte[] iv) {
        return new IvParameterSpec(iv);
    }

    @Override
    public EncryptionResult encrypt(EncryptionRequest req) throws CryptoException {
        try {
            Assert.notNull(req, "EncryptionRequest cannot be null.");
            return doEncrypt(req);
        } catch (Exception e) {
            String msg = "Unable to perform encryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected byte[] generateInitializationValue(SecureRandom random) {
        byte[] iv = new byte[this.generatedIvLength];
        random.nextBytes(iv);
        return iv;
    }

    protected SecureRandom getSecureRandom(EncryptionRequest request) {
        SecureRandom random = request.getSecureRandom();
        return random != null ? random : DEFAULT_RANDOM;
    }

    protected byte[] assertKey(CryptoRequest request) {
        byte[] key = request.getKey();
        return assertKeyLength(key);
    }

    protected byte[] assertKeyLength(byte[] key) {
        int length = length(key);
        if (length != requiredKeyLength) {
            throw new CryptoException("The " + getName() + " algorithm requires that keys have a key length of " +
                    "(preferrably secure-random) " + requiredKeyLength + " bytes (" +
                    requiredKeyLength * Byte.SIZE + " bits). The provided key has a length of " +
                    length + " bytes (" + length * Byte.SIZE + " bits).");
        }
        return key;
    }

    protected byte[] ensureEncryptionIv(EncryptionRequest req) {

        final SecureRandom random = getSecureRandom(req);

        byte[] iv = req.getInitializationValue();

        int ivLength = length(iv);
        if (ivLength == 0) {
            iv = generateInitializationValue(random);
        }

        return iv;
    }

    protected byte[] assertDecryptionIv(DecryptionRequest req) throws IllegalArgumentException {
        byte[] iv = req.getInitializationValue();
        Assert.notEmpty(iv, DECRYPT_NO_IV);
        return iv;
    }

    protected byte[] getAAD(CryptoRequest request) {
        if (request instanceof AssociatedDataSource) {
            byte[] aad = ((AssociatedDataSource) request).getAssociatedData();
            return io.jsonwebtoken.lang.Arrays.clean(aad);
        }
        return null;
    }

    protected abstract EncryptionResult doEncrypt(EncryptionRequest req) throws Exception;


    @Override
    public byte[] decrypt(DecryptionRequest req) throws CryptoException {
        try {
            Assert.notNull(req, "DecryptionRequest cannot be null.");
            return doDecrypt(req);
        } catch (Exception e) {
            String msg = "Unable to perform decryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected abstract byte[] doDecrypt(DecryptionRequest req) throws Exception;
}
