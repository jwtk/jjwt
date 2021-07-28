package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadResult;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.PayloadSupplier;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.SignatureRequest;
import io.jsonwebtoken.security.SymmetricAeadAlgorithm;
import io.jsonwebtoken.security.SymmetricAeadDecryptionRequest;
import io.jsonwebtoken.security.SymmetricAeadRequest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class HmacAesAeadAlgorithm extends AesAlgorithm implements SymmetricAeadAlgorithm {

    private static final String TRANSFORMATION_STRING = "AES/CBC/PKCS5Padding";

    private final MacSignatureAlgorithm SIGALG;

    private static int digestLength(int keyLength) {
        return keyLength * 2;
    }

    private static String id(int keyLength) {
        return "A" + keyLength + "CBC-HS" + digestLength(keyLength);
    }

    public HmacAesAeadAlgorithm(String id, MacSignatureAlgorithm sigAlg) {
        super(id, TRANSFORMATION_STRING, sigAlg.getMinKeyLength());
        this.SIGALG = sigAlg;
    }

    @SuppressWarnings("unused") //Used via reflection by io.jsonwebtoken.security.EncryptionAlgorithms
    public HmacAesAeadAlgorithm(int keyLength) {
        this(id(keyLength), new MacSignatureAlgorithm(id(keyLength), "HmacSHA" + digestLength(keyLength), keyLength));
    }

    @Override
    public SecretKey generateKey() {
        return new JcaTemplate("AES", null).generateSecretKey(this.keyLength * 2);
    }

    byte[] assertKeyBytes(CryptoRequest<?, SecretKey> request) {
        SecretKey key = Assert.notNull(request.getKey(), "Request key cannot be null.");
        return validateLength(key, this.keyLength * 2, true);
    }

    @Override
    public AeadResult encrypt(final SymmetricAeadRequest req) {

        Assert.notNull(req, "Request cannot be null.");

        byte[] compositeKeyBytes = assertKeyBytes(req);
        int halfCount = compositeKeyBytes.length / 2; // https://tools.ietf.org/html/rfc7518#section-5.2
        byte[] macKeyBytes = Arrays.copyOfRange(compositeKeyBytes, 0, halfCount);
        byte[] encKeyBytes = Arrays.copyOfRange(compositeKeyBytes, halfCount, compositeKeyBytes.length);
        final SecretKey encryptionKey = new SecretKeySpec(encKeyBytes, "AES");

        final byte[] plaintext = Assert.notEmpty(req.getPayload(), "Request payload (plaintext) cannot be null or empty.");
        final byte[] aad = getAAD(req); //can be null if request associated data does not exist or is empty
        final byte[] iv = ensureInitializationVector(req);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        final byte[] ciphertext = execute(req, Cipher.class, new InstanceCallback<Cipher, byte[]>() {
            @Override
            public byte[] doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivSpec);
                return cipher.doFinal(plaintext);
            }
        });

        byte[] tag = sign(aad, iv, ciphertext, macKeyBytes);

        return new DefaultAeadResult(req.getProvider(), req.getSecureRandom(), ciphertext, encryptionKey, aad, tag, iv);
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
        return assertTag(Arrays.copyOfRange(digest, 0, macKeyBytes.length));
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
    public PayloadSupplier<byte[]> decrypt(final SymmetricAeadDecryptionRequest req) {

        Assert.notNull(req, "Request cannot be null.");

        byte[] compositeKeyBytes = assertKeyBytes(req);
        int halfCount = compositeKeyBytes.length / 2; // https://tools.ietf.org/html/rfc7518#section-5.2
        byte[] macKeyBytes = Arrays.copyOfRange(compositeKeyBytes, 0, halfCount);
        byte[] encKeyBytes = Arrays.copyOfRange(compositeKeyBytes, halfCount, compositeKeyBytes.length);
        final SecretKey decryptionKey = new SecretKeySpec(encKeyBytes, "AES");

        final byte[] ciphertext = Assert.notEmpty(req.getPayload(), "Decryption request payload (ciphertext) cannot be null or empty.");
        final byte[] aad = getAAD(req);
        final byte[] tag = assertTag(req.getAuthenticationTag());
        final byte[] iv = assertDecryptionIv(req);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        // Assert that the aad + iv + ciphertext provided, when signed, equals the tag provided,
        // thereby verifying none of it has been tampered with:
        byte[] digest = sign(aad, iv, ciphertext, macKeyBytes);
        if (!MessageDigest.isEqual(digest, tag)) { //constant time comparison to avoid side-channel attacks
            String msg = "Ciphertext decryption failed: Authentication tag verification failed.";
            throw new SignatureException(msg);
        }

        byte[] plaintext = execute(req, Cipher.class, new InstanceCallback<Cipher, byte[]>() {
            @Override
            public byte[] doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
                return cipher.doFinal(ciphertext);
            }
        });

        return new DefaultPayloadSupplier<>(plaintext);
    }
}
