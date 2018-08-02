package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.RuntimeEnvironment;
import io.jsonwebtoken.security.AeadIvRequest;
import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.AeadIvEncryptionResult;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class GcmAesEncryptionAlgorithm extends AbstractAeadAesEncryptionAlgorithm {

    //TODO: Remove this static block when JDK 7 support is removed
    // JDK <= 7 does not support AES GCM mode natively and so BouncyCastle is required
    static {
        RuntimeEnvironment.enableBouncyCastleIfPossible();
    }

    private static final int GCM_IV_SIZE_BITS = 96; // https://tools.ietf.org/html/rfc7518#section-5.3
    private static final String TRANSFORMATION_STRING = "AES/GCM/NoPadding";

    public GcmAesEncryptionAlgorithm(String name, int requiredKeyLengthInBits) {
        super(name, TRANSFORMATION_STRING, GCM_IV_SIZE_BITS, requiredKeyLengthInBits);
        //Standard AES only supports 128, 192, and 256 key lengths, respectively:
        Assert.isTrue(requiredKeyLengthInBits == 128 || requiredKeyLengthInBits == 192 || requiredKeyLengthInBits == 256, "Invalid AES Key length.");
    }

    @Override
    protected AeadIvEncryptionResult doEncrypt(final AeadRequest<byte[], SecretKey> req) throws Exception {

        //Ensure IV:
        final byte[] iv =  ensureInitializationVector(req);

        //Ensure Key:
        final SecretKey encryptionKey = assertKey(req);

        //See if there is any AAD:
        final byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        byte[] ciphertext = newCipherTemplate(req).execute(new CipherCallback<byte[]>() {
            @Override
            public byte[] doWithCipher(Cipher cipher) throws Exception {
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(AES_BLOCK_SIZE_BITS, iv));
                if (aad != null) {
                    cipher.updateAAD(aad);
                }
                return cipher.doFinal(req.getData());
            }
        });

        // When using GCM mode, the JDK actually appends the authentication tag to the ciphertext, so let's
        // represent this appropriately:
        byte[] taggedCiphertext = ciphertext;

        // Now separate the tag from the ciphertext (tag has a length of AES_BLOCK_SIZE_BITS):
        int ciphertextLength = taggedCiphertext.length - AES_BLOCK_SIZE_BYTES;
        ciphertext = new byte[ciphertextLength];
        System.arraycopy(taggedCiphertext, 0, ciphertext, 0, ciphertextLength);

        byte[] tag = new byte[AES_BLOCK_SIZE_BYTES];
        System.arraycopy(taggedCiphertext, ciphertextLength, tag, 0, AES_BLOCK_SIZE_BYTES);

        return new DefaultAeadIvEncryptionResult(ciphertext, iv, tag);
    }

    @Override
    protected byte[] doDecrypt(AeadIvRequest<byte[], SecretKey> req) throws Exception {

        final byte[] tag = req.getAuthenticationTag();
        Assert.notEmpty(tag, "AeadDecryptionRequests must include a non-empty authentication tag.");

        final byte[] iv = assertDecryptionIv(req);

        //Ensure Key:
        final SecretKey decryptionKey = assertKey(req);

        //See if there is any AAD:
        final byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        final byte[] ciphertext = req.getData();

        return newCipherTemplate(req).execute(new CipherCallback<byte[]>() {
            @Override
            public byte[] doWithCipher(Cipher cipher) throws Exception {
                cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new GCMParameterSpec(AES_BLOCK_SIZE_BITS, iv));

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
        });
    }
}
