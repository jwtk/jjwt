package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadIvRequest;
import io.jsonwebtoken.security.AeadIvEncryptionResult;
import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

/**
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings("unused") //used via reflection in the io.jsonwebtoken.security.EncryptionAlgorithms class
public class HmacAesEncryptionAlgorithm extends AbstractAeadAesEncryptionAlgorithm {

    private static final String TRANSFORMATION_STRING = "AES/CBC/PKCS5Padding";

    private final MacSignatureAlgorithm SIGALG;

    public HmacAesEncryptionAlgorithm(String name, MacSignatureAlgorithm sigAlg) {
        super(name, TRANSFORMATION_STRING, AES_BLOCK_SIZE_BITS, sigAlg.getMinKeyLength() * 2);
        this.SIGALG = sigAlg;
    }

    @Override
    protected SecretKey doGenerateKey() throws Exception {

        int subKeyLength = getRequiredKeyByteLength() / 2;

        byte[] macKeyBytes = this.SIGALG.generateKey().getEncoded();
        Assert.notEmpty(macKeyBytes, "Generated HMAC key byte array cannot be null or empty.");

        if (macKeyBytes.length > subKeyLength) {
            byte[] subKeyBytes = new byte[subKeyLength];
            System.arraycopy(macKeyBytes, 0, subKeyBytes, 0, subKeyLength);
            macKeyBytes = subKeyBytes;
        }

        if (macKeyBytes.length != subKeyLength) {
            String msg = "The delegate MacSignatureAlgorithm instance of type {" + SIGALG.getClass().getName() + "} " +
                    "generated a key " + macKeyBytes.length + " bytes (" +
                    macKeyBytes.length * Byte.SIZE + " bits) long.  The " + getName() + " algorithm requires " +
                "SignatureAlgorithm keys to be " + subKeyLength + " bytes (" +
                subKeyLength * Byte.SIZE + " bits) long.";
            throw new IllegalStateException(msg);
        }

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(subKeyLength * Byte.SIZE);

        SecretKey encKey = keyGenerator.generateKey();
        byte[] encKeyBytes = encKey.getEncoded();

        //return as one single key per https://tools.ietf.org/html/rfc7518#section-5.2.2.1

        byte[] combinedKeyBytes = new byte[macKeyBytes.length + encKeyBytes.length];

        System.arraycopy(macKeyBytes, 0, combinedKeyBytes, 0, macKeyBytes.length);
        System.arraycopy(encKeyBytes, 0, combinedKeyBytes, macKeyBytes.length, encKeyBytes.length);

        return new SecretKeySpec(combinedKeyBytes, "AES");
    }

    byte[] assertKeyBytes(CryptoRequest<?, SecretKey> request) {
        SecretKey key = assertKey(request);
        return key.getEncoded();
    }

    @Override
    protected AeadIvEncryptionResult doEncrypt(final AeadRequest<byte[], SecretKey> req) throws Exception {

        //Ensure IV:
        final byte[] iv = ensureInitializationVector(req);

        //Ensure Key:
        byte[] keyBytes = assertKeyBytes(req);

        //See if there is any AAD:
        final byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        int halfCount = keyBytes.length / 2; // https://tools.ietf.org/html/rfc7518#section-5.2
        byte[] macKeyBytes = Arrays.copyOfRange(keyBytes, 0, halfCount);
        keyBytes = Arrays.copyOfRange(keyBytes, halfCount, keyBytes.length);

        final SecretKey encryptionKey = new SecretKeySpec(keyBytes, "AES");

        final byte[] ciphertext = newCipherTemplate(req).execute(new CipherCallback<byte[]>() {
            @Override
            public byte[] doWithCipher(Cipher cipher) throws Exception {
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
                byte[] plaintext = req.getData();
                return cipher.doFinal(plaintext);
            }
        });

        byte[] tag = sign(aad, iv, ciphertext, macKeyBytes);

        return new DefaultAeadIvEncryptionResult(ciphertext, iv, tag);
    }

    private byte[] sign(byte[] aad, byte[] iv, byte[] ciphertext, byte[] macKeyBytes) {

        long aadLength = io.jsonwebtoken.lang.Arrays.length(aad);
        long aadLengthInBits = aadLength * Byte.SIZE;
        long aadLengthInBitsAsUnsignedInt = aadLengthInBits & 0xffffffffL;
        byte[] AL = toBytes(aadLengthInBitsAsUnsignedInt);

        byte[] toHash = new byte[(int) aadLength + iv.length + ciphertext.length + AL.length];

        if (aad != null) {
            System.arraycopy(aad, 0, toHash, 0, aad.length);
            System.arraycopy(iv, 0, toHash, aad.length, iv.length);
            System.arraycopy(ciphertext, 0, toHash, aad.length + iv.length, ciphertext.length);
            System.arraycopy(AL, 0, toHash, aad.length + iv.length + ciphertext.length, AL.length);
        } else {
            System.arraycopy(iv, 0, toHash, 0, iv.length);
            System.arraycopy(ciphertext, 0, toHash, iv.length, ciphertext.length);
            System.arraycopy(AL, 0, toHash, iv.length + ciphertext.length, AL.length);
        }

        Key key = new SecretKeySpec(macKeyBytes, SIGALG.getJcaName());
        CryptoRequest<byte[], Key> request = new DefaultCryptoRequest<>(toHash, key, null, null);
        byte[] digest = SIGALG.sign(request);

        // https://tools.ietf.org/html/rfc7518#section-5.2.2.1 #5 requires truncating the signature
        // to be the same length as the macKey/encKey:
        return Arrays.copyOfRange(digest, 0, macKeyBytes.length);
    }

    private static byte[] toBytes(long l) {
        byte[] b = new byte[8];
        for (int i = 7; i > 0; i--) {
            b[i] = (byte) l;
            l >>>= 8;
        }
        b[0] = (byte) l;
        return b;
    }

    @Override
    protected byte[] doDecrypt(AeadIvRequest<byte[], SecretKey> req) throws Exception {

        byte[] tag = req.getAuthenticationTag();
        Assert.notEmpty(tag, "AeadDecryptionRequests must include a non-empty authentication tag.");

        final byte[] iv = assertDecryptionIv(req);

        //Ensure Key:
        byte[] keyBytes = assertKeyBytes(req);

        //See if there is any AAD:
        byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty

        int halfCount = keyBytes.length / 2; // https://tools.ietf.org/html/rfc7518#section-5.2
        byte[] macKeyBytes = Arrays.copyOfRange(keyBytes, 0, halfCount);
        keyBytes = Arrays.copyOfRange(keyBytes, halfCount, keyBytes.length);

        final SecretKey decryptionKey = new SecretKeySpec(keyBytes, "AES");

        final byte[] ciphertext = req.getData();

        // Assert that the aad + iv + ciphertext provided, when signed, equals the tag provided,
        // thereby indicating none of it has been tampered with:
        byte[] digest = sign(aad, iv, ciphertext, macKeyBytes);
        if (!Arrays.equals(digest, tag)) {
            String msg = "Ciphertext decryption failed: Authentication tag verification failed.";
            throw new SignatureException(msg);
        }

        return newCipherTemplate(req).execute(new CipherCallback<byte[]>() {
            @Override
            public byte[] doWithCipher(Cipher cipher) throws Exception {
                cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(iv));
                return cipher.doFinal(ciphertext);
            }
        });
    }
}
