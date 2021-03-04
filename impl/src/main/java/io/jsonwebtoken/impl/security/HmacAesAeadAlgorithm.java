package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.SignatureRequest;
import io.jsonwebtoken.security.SymmetricAeadDecryptionRequest;
import io.jsonwebtoken.security.SymmetricAeadEncryptionResult;
import io.jsonwebtoken.security.SymmetricAeadRequest;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class HmacAesAeadAlgorithm extends AesAeadAlgorithm {

    private static final String TRANSFORMATION_STRING = "AES/CBC/PKCS5Padding";

    private final MacSignatureAlgorithm SIGALG;

    private static int digestLength(int keyLength) {
        return keyLength * 2;
    }

    private static String id(int keyLength) {
        return "A" + keyLength + "CBC-HS" + digestLength(keyLength);
    }

    public HmacAesAeadAlgorithm(String id, MacSignatureAlgorithm sigAlg) {
        super(id, TRANSFORMATION_STRING, AES_BLOCK_SIZE_BITS, sigAlg.getMinKeyLength() * 2);
        this.SIGALG = sigAlg;
    }

    @SuppressWarnings("unused") //Used via reflection by io.jsonwebtoken.security.EncryptionAlgorithms
    public HmacAesAeadAlgorithm(int keyLength) {
        this(id(keyLength), new MacSignatureAlgorithm(id(keyLength), "HmacSHA" + digestLength(keyLength), keyLength));
        Assert.isTrue(keyLength == 128 || keyLength == 192 || keyLength == 256, "Invalid AES keyLength - it must equal 128, 192, or 256.");
    }

    @Override
    public SecretKey generateKey() {

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
                macKeyBytes.length * Byte.SIZE + " bits) long.  The " + getId() + " algorithm requires " +
                "SignatureAlgorithm keys to be " + subKeyLength + " bytes (" +
                subKeyLength * Byte.SIZE + " bits) long.";
            throw new IllegalStateException(msg);
        }

        SecretKey encKey = new JcaTemplate("AES", null).generateSecretKey(subKeyLength * Byte.SIZE);
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
    protected SymmetricAeadEncryptionResult doEncrypt(final SymmetricAeadRequest req) {

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

        final byte[] ciphertext = execute(req, Cipher.class, new InstanceCallback<Cipher, byte[]>() {
            @Override
            public byte[] doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
                byte[] plaintext = req.getPayload();
                return cipher.doFinal(plaintext);
            }
        });

        byte[] tag = sign(aad, iv, ciphertext, macKeyBytes);

        return new DefaultSymmetricAeadResult(req.getProvider(), req.getSecureRandom(), ciphertext, encryptionKey, aad, tag, iv);
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

        SecretKey key = new SecretKeySpec(macKeyBytes, SIGALG.getJcaName());
        SignatureRequest<SecretKey> request = new DefaultSignatureRequest<>(null, null, toHash, key);
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
    protected byte[] doDecrypt(final SymmetricAeadDecryptionRequest req) {

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

        final byte[] ciphertext = req.getPayload();

        // Assert that the aad + iv + ciphertext provided, when signed, equals the tag provided,
        // thereby indicating none of it has been tampered with:
        byte[] digest = sign(aad, iv, ciphertext, macKeyBytes);
        if (!MessageDigest.isEqual(digest, tag)) {
            String msg = "Ciphertext decryption failed: Authentication tag verification failed.";
            throw new SignatureException(msg);
        }

        return execute(req, Cipher.class, new InstanceCallback<Cipher, byte[]>() {
            @Override
            public byte[] doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(iv));
                return cipher.doFinal(ciphertext);
            }
        });
    }
}
