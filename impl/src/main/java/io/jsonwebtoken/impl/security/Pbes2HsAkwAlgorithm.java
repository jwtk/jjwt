package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.ValueGetter;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.PbeKey;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;

public class Pbes2HsAkwAlgorithm extends CryptoAlgorithm implements KeyAlgorithm<PbeKey, SecretKey> {

    private static final String SALT_HEADER_NAME = "p2s";
    private static final String ITERATION_HEADER_NAME = "p2c"; // iteration count
    private static final int MIN_RECOMMENDED_ITERATIONS = 1000; // https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2

    private final int HASH_BYTE_LENGTH;
    private final int DERIVED_KEY_BIT_LENGTH;
    private final byte[] SALT_PREFIX;
    private final KeyAlgorithm<SecretKey, SecretKey> wrapAlg;

    private static byte[] toRfcSaltPrefix(byte[] bytes) {
        // last byte must always be zero as it is a delimiter per
        // https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.1
        // We ensure this by creating a byte array that is one element larger than bytes.length since Java defaults all
        // new byte array indices to 0x00, meaning the last one will be our zero delimiter:
        byte[] output = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, output, 0, bytes.length);
        return output;
    }

    private static int hashBitLength(int keyBitLength) {
        return keyBitLength * 2;
    }

    private static String idFor(int hashBitLength, KeyAlgorithm<SecretKey, SecretKey> wrapAlg) {
        Assert.notNull(wrapAlg, "wrapAlg argument cannot be null.");
        return "PBES2-HS" + hashBitLength + "+" + wrapAlg.getId();
    }

    public static int assertIterations(int iterations) {
        if (iterations < MIN_RECOMMENDED_ITERATIONS) {
            String msg = "[JWA RFC 7518, Section 4.8.1.2](https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2) " +
                "recommends password-based-encryption iterations be greater than or equal to " +
                MIN_RECOMMENDED_ITERATIONS + ". Provided: " + iterations;
            throw new IllegalArgumentException(msg);
        }
        return iterations;
    }

    public Pbes2HsAkwAlgorithm(int keyBitLength) {
        this(hashBitLength(keyBitLength), new AesWrapKeyAlgorithm(keyBitLength));
    }

    private Pbes2HsAkwAlgorithm(int hashBitLength, KeyAlgorithm<SecretKey, SecretKey> wrapAlg) {
        super(idFor(hashBitLength, wrapAlg), "PBKDF2WithHmacSHA" + hashBitLength);
        this.wrapAlg = wrapAlg; // no need to assert non-null due to 'idFor' implementation above

        // There's some white box knowledge here: there is no need to assert the value of hashBitLength
        // because that is done implicitly in the constructor when instantiating AesWrapKeyAlgorithm. See that class's
        // implementation to see the assertion:
        this.HASH_BYTE_LENGTH = hashBitLength / Byte.SIZE;

        // https://datatracker.ietf.org/doc/html/rfc7518#section-4.8, 2nd paragraph, last sentence:
        // "Their derived-key lengths respectively are 16, 24, and 32 octets." :
        this.DERIVED_KEY_BIT_LENGTH = hashBitLength / 2; // results in 128, 192, or 256

        this.SALT_PREFIX = toRfcSaltPrefix(getId().getBytes(StandardCharsets.UTF_8));
    }

    // protected visibility for testing
    protected SecretKey deriveKey(SecretKeyFactory factory, final char[] password, final byte[] rfcSalt, int iterations) throws Exception {
        PBEKeySpec spec = null;
        try {
            spec = new PBEKeySpec(password, rfcSalt, iterations, DERIVED_KEY_BIT_LENGTH);
            return factory.generateSecret(spec);
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
        }
    }

    private SecretKey deriveKey(final KeyRequest<?> request, final char[] password, final byte[] salt, final int iterations) {
        try {
            return execute(request, SecretKeyFactory.class, new CheckedFunction<SecretKeyFactory, SecretKey>() {
                @Override
                public SecretKey apply(SecretKeyFactory factory) throws Exception {
                    return deriveKey(factory, password, salt, iterations);
                }
            });
        } finally {
            if (password != null) {
                java.util.Arrays.fill(password, '\u0000');
            }
        }
    }

    protected byte[] generateInputSalt(KeyRequest<?> request) {
        byte[] inputSalt = new byte[this.HASH_BYTE_LENGTH];
        ensureSecureRandom(request).nextBytes(inputSalt);
        return inputSalt;
    }

    // protected visibility for testing
    protected byte[] toRfcSalt(byte[] inputSalt) {
        return Bytes.concat(this.SALT_PREFIX, inputSalt);
    }

    @Override
    public KeyResult getEncryptionKey(KeyRequest<PbeKey> request) throws SecurityException {

        Assert.notNull(request, "request cannot be null.");
        final PbeKey pbeKey = Assert.notNull(request.getKey(), "request.getKey() cannot be null.");

        final int iterations = assertIterations(pbeKey.getWorkFactor());
        byte[] inputSalt = generateInputSalt(request);
        final byte[] rfcSalt = toRfcSalt(inputSalt);
        final String p2s = Encoders.BASE64URL.encode(inputSalt);
        char[] password = pbeKey.getPassword(); // will be safely cleaned/zeroed in deriveKey next:
        final SecretKey derivedKek = deriveKey(request, password, rfcSalt, iterations);

        // now get a new CEK that is encrypted ('wrapped') with the PBE-derived key:
        DefaultKeyRequest<SecretKey> wrapReq = new DefaultKeyRequest<>(request.getProvider(),
            request.getSecureRandom(), derivedKek, request.getHeader(), request.getEncryptionAlgorithm());
        KeyResult result = wrapAlg.getEncryptionKey(wrapReq);

        request.getHeader().put(SALT_HEADER_NAME, p2s);
        request.getHeader().put(ITERATION_HEADER_NAME, iterations);

        return result;
    }

    private static char[] toChars(byte[] bytes) {
        // use bytebuffer/charbuffer so we don't create a String that remains in the JVM string memory table (heap)
        // the respective byte and char arrays will be cleared by the caller
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        CharBuffer cbuf = StandardCharsets.UTF_8.decode(buf);
        return cbuf.compact().array();
    }

    private char[] toPasswordChars(SecretKey key) {
        if (key instanceof PBEKey) {
            return ((PBEKey) key).getPassword();
        }
        if (key instanceof PbeKey) {
            return ((PbeKey) key).getPassword();
        }
        // convert bytes to UTF-8 characters:
        byte[] keyBytes = null;
        try {
            keyBytes = key.getEncoded();
            return toChars(keyBytes);
        } finally {
            if (keyBytes != null) {
                java.util.Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<SecretKey> request) throws SecurityException {

        JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        final SecretKey key = Assert.notNull(request.getKey(), "Request Key cannot be null.");

        ValueGetter getter = new DefaultValueGetter(header);
        final byte[] inputSalt = getter.getRequiredBytes(SALT_HEADER_NAME);
        final byte[] rfcSalt = Bytes.concat(SALT_PREFIX, inputSalt);
        final int iterations = getter.getRequiredPositiveInteger(ITERATION_HEADER_NAME);
        final char[] password = toPasswordChars(key); // will be safely cleaned/zeroed in deriveKey next:

        final SecretKey derivedKek = deriveKey(request, password, rfcSalt, iterations);

        DecryptionKeyRequest<SecretKey> unwrapReq = new DefaultDecryptionKeyRequest<>(request.getProvider(),
            request.getSecureRandom(), derivedKek, header, request.getEncryptionAlgorithm(), request.getPayload());

        return wrapAlg.getDecryptionKey(unwrapReq);
    }
}
