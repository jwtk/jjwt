package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.impl.DefaultJweHeader;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.CheckedSupplier;
import io.jsonwebtoken.impl.lang.Conditions;
import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.RequiredFieldReader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.PasswordKey;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class Pbes2HsAkwAlgorithm extends CryptoAlgorithm implements KeyAlgorithm<PasswordKey, PasswordKey> {

    // See https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2 :
    private static final int DEFAULT_SHA256_ITERATIONS = 310000;
    private static final int DEFAULT_SHA384_ITERATIONS = 210000;
    private static final int DEFAULT_SHA512_ITERATIONS = 120000;

    private static final int MIN_RECOMMENDED_ITERATIONS = 1000; // https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2
    private static final String MIN_ITERATIONS_MSG_PREFIX =
        "[JWA RFC 7518, Section 4.8.1.2](https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2) " +
            "recommends password-based-encryption iterations be greater than or equal to " +
            MIN_RECOMMENDED_ITERATIONS + ". Provided: ";

    private final int HASH_BYTE_LENGTH;
    private final int DERIVED_KEY_BIT_LENGTH;
    private final byte[] SALT_PREFIX;
    private final int DEFAULT_ITERATIONS;
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
            String msg = MIN_ITERATIONS_MSG_PREFIX + iterations;
            throw new IllegalArgumentException(msg);
        }
        return iterations;
    }

    public Pbes2HsAkwAlgorithm(int keyBitLength) {
        this(hashBitLength(keyBitLength), new AesWrapKeyAlgorithm(keyBitLength));
    }

    protected Pbes2HsAkwAlgorithm(int hashBitLength, KeyAlgorithm<SecretKey, SecretKey> wrapAlg) {
        super(idFor(hashBitLength, wrapAlg), "PBKDF2WithHmacSHA" + hashBitLength);
        this.wrapAlg = wrapAlg; // no need to assert non-null due to 'idFor' implementation above

        // There's some white box knowledge here: there is no need to assert the value of hashBitLength
        // because that is done implicitly in the constructor when instantiating AesWrapKeyAlgorithm. See that class's
        // implementation to see the assertion:
        this.HASH_BYTE_LENGTH = hashBitLength / Byte.SIZE;

        // If the JwtBuilder caller doesn't specify an iteration count, fall back to OWASP best-practice recommendations
        // per https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        if (hashBitLength >= 512) {
            DEFAULT_ITERATIONS = DEFAULT_SHA512_ITERATIONS;
        } else if (hashBitLength >= 384) {
            DEFAULT_ITERATIONS = DEFAULT_SHA384_ITERATIONS;
        } else {
            DEFAULT_ITERATIONS = DEFAULT_SHA256_ITERATIONS;
        }

        // https://datatracker.ietf.org/doc/html/rfc7518#section-4.8, 2nd paragraph, last sentence:
        // "Their derived-key lengths respectively are 16, 24, and 32 octets." :
        this.DERIVED_KEY_BIT_LENGTH = hashBitLength / 2; // results in 128, 192, or 256

        this.SALT_PREFIX = toRfcSaltPrefix(getId().getBytes(StandardCharsets.UTF_8));

        // PBKDF2WithHmacSHA* algorithms are only available on JDK 8 and later, so enable BC as a backup provider if
        // necessary for <= JDK 7:
        // TODO: remove when dropping Java 7 support:
        setProvider(Providers.findBouncyCastle(Conditions.notExists(new CheckedSupplier<SecretKeyFactory>() {
            @Override
            public SecretKeyFactory get() throws Exception {
                return SecretKeyFactory.getInstance(getJcaName());
            }
        })));
    }

    // protected visibility for testing
    protected SecretKey deriveKey(SecretKeyFactory factory, final char[] password, final byte[] rfcSalt, int iterations) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, rfcSalt, iterations, DERIVED_KEY_BIT_LENGTH);
        try {
            SecretKey derived = factory.generateSecret(spec);
            return new WrappedSecretKey(derived, "AES"); // needed to keep the Sun Provider happy.  BC doesn't care.
        } finally {
            spec.clearPassword();
        }
    }

    private SecretKey deriveKey(final KeyRequest<?> request, final char[] password, final byte[] salt, final int iterations) {
        Assert.notEmpty(password, "Key password character array cannot be null or empty.");
        try {
            return execute(request, SecretKeyFactory.class, new CheckedFunction<SecretKeyFactory, SecretKey>() {
                @Override
                public SecretKey apply(SecretKeyFactory factory) throws Exception {
                    return deriveKey(factory, password, salt, iterations);
                }
            });
        } finally {
            java.util.Arrays.fill(password, '\u0000');
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
    public KeyResult getEncryptionKey(KeyRequest<PasswordKey> request) throws SecurityException {

        Assert.notNull(request, "request cannot be null.");
        final PasswordKey key = Assert.notNull(request.getKey(), "request.getKey() cannot be null.");
        Integer p2c = request.getHeader().getPbes2Count();
        if (p2c == null) {
            p2c = DEFAULT_ITERATIONS;
            request.getHeader().setPbes2Count(p2c);
        }
        final int iterations = assertIterations(p2c);
        byte[] inputSalt = generateInputSalt(request);
        final byte[] rfcSalt = toRfcSalt(inputSalt);
        char[] password = key.getPassword(); // password will be safely cleaned/zeroed in deriveKey next:
        final SecretKey derivedKek = deriveKey(request, password, rfcSalt, iterations);

        // now get a new CEK that is encrypted ('wrapped') with the PBE-derived key:
        DefaultKeyRequest<SecretKey> wrapReq = new DefaultKeyRequest<>(request.getProvider(),
            request.getSecureRandom(), derivedKek, request.getHeader(), request.getEncryptionAlgorithm());
        KeyResult result = wrapAlg.getEncryptionKey(wrapReq);

        request.getHeader().put(DefaultJweHeader.P2S.getId(), inputSalt); //retain for recipients

        return result;
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<PasswordKey> request) throws SecurityException {

        JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        final PasswordKey key = Assert.notNull(request.getKey(), "Request Key cannot be null.");
        FieldReadable reader = new RequiredFieldReader(header);
        final byte[] inputSalt = reader.get(DefaultJweHeader.P2S);
        final int iterations = reader.get(DefaultJweHeader.P2C);
        final byte[] rfcSalt = Bytes.concat(SALT_PREFIX, inputSalt);
        final char[] password = key.getPassword(); // password will be safely cleaned/zeroed in deriveKey next:
        final SecretKey derivedKek = deriveKey(request, password, rfcSalt, iterations);

        DecryptionKeyRequest<SecretKey> unwrapReq = new DefaultDecryptionKeyRequest<>(request.getProvider(),
            request.getSecureRandom(), derivedKek, header, request.getEncryptionAlgorithm(), request.getContent());

        return wrapAlg.getDecryptionKey(unwrapReq);
    }
}
