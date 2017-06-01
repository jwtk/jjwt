package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.lang.Assert;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.AlgorithmParameterSpec;

public class GcmAesEncryptionAlgorithm extends AbstractAesEncryptionAlgorithm {

    private static final int GCM_IV_SIZE = 12; //number of bytes, not bits. 12 is recommended for GCM for efficiency
    private static final String TRANSFORMATION_STRING = "AES/GCM/NoPadding";

    public GcmAesEncryptionAlgorithm(String name, int requiredKeyLength) {
        super(name, TRANSFORMATION_STRING, GCM_IV_SIZE, requiredKeyLength);
        //Standard AES only supports 128, 192, and 256 key lengths, respectively:
        Assert.isTrue(requiredKeyLength == 16 || requiredKeyLength == 24 || requiredKeyLength == 32, "Invalid AES Key length.");
    }

    @Override
    protected AlgorithmParameterSpec createAlgorithmParameterSpec(byte[] iv) {
        return new GCMParameterSpec(AES_BLOCK_SIZE * Byte.SIZE, iv);
    }

    @Override
    protected EncryptionResult doEncrypt(EncryptionRequest req) throws Exception {

        //Ensure IV:
        byte[] iv = ensureEncryptionIv(req);

        //Ensure Key:
        byte[] keyBytes = assertKey(req);

        //See if there is any AAD:
        byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        final SecretKey encryptionKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, encryptionKey, iv);
        if (aad != null) {
            cipher.updateAAD(aad);
        }

        byte[] plaintext = req.getPlaintext();
        byte[] ciphertext = cipher.doFinal(plaintext);

        // When using GCM mode, the JDK actually appends the authentication tag to the ciphertext, so let's
        // represent this appropriately:
        byte[] taggedCiphertext = ciphertext;

        // Now separate the tag from the ciphertext (tag has a length of AES_BLOCK_SIZE):
        int ciphertextLength = taggedCiphertext.length - AES_BLOCK_SIZE;
        ciphertext = new byte[ciphertextLength];
        System.arraycopy(taggedCiphertext, 0, ciphertext, 0, ciphertextLength);

        byte[] tag = new byte[AES_BLOCK_SIZE];
        System.arraycopy(taggedCiphertext, ciphertextLength, tag, 0, AES_BLOCK_SIZE);

        return new DefaultAuthenticatedEncryptionResult(iv, ciphertext, tag);
    }

    @Override
    protected byte[] doDecrypt(DecryptionRequest dreq) throws Exception {

        Assert.isInstanceOf(AuthenticatedDecryptionRequest.class, dreq,
                "AES GCM encryption always authenticates and therefore requires that DecryptionRequests are " +
                        "AuthenticatedDecryptionRequest instances.");
        AuthenticatedDecryptionRequest req = (AuthenticatedDecryptionRequest) dreq;

        byte[] tag = req.getAuthenticationTag();
        Assert.notEmpty(tag, "AuthenticatedDecryptionRequests must include a non-empty authentication tag.");

        byte[] iv = assertDecryptionIv(req);

        //Ensure Key:
        byte[] keyBytes = assertKey(req);

        //See if there is any AAD:
        byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        final SecretKey key = new SecretKeySpec(keyBytes, "AES");

        final byte[] ciphertext = req.getCiphertext();

        Cipher cipher = createCipher(Cipher.DECRYPT_MODE, key, iv);

        if (aad != null) {
            cipher.updateAAD(aad);
        }

        //for tagged GCM, the JVM spec requires that the tag be appended to the end of the ciphertext
        //byte array.  So we'll append it here:
        byte[] taggedCiphertext = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, taggedCiphertext, 0, ciphertext.length);
        System.arraycopy(tag, 0, taggedCiphertext, ciphertext.length, tag.length);

        return cipher.doFinal(taggedCiphertext);
    }
}
