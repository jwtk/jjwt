package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EncryptedKeyAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;

public class Pbes2HsAkwAlgorithm extends CryptoAlgorithm implements EncryptedKeyAlgorithm<SecretKey, SecretKey> {

    private static final String SALT_HEADER_NAME = "p2s";
    private static final String ITERATION_HEADER_NAME = "p2c"; // iteration count

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

    private SecretKey deriveKey(final KeyRequest<?, ?> request, final PBEKey pbeKey, final byte[] salt, final int iterations) {
        return execute(request, SecretKeyFactory.class, new InstanceCallback<SecretKeyFactory, SecretKey>() {
            @Override
            public SecretKey doWithInstance(SecretKeyFactory factory) throws Exception {
                PBEKeySpec spec = null;
                try {
                    spec = new PBEKeySpec(pbeKey.getPassword(), salt, iterations, DERIVED_KEY_BIT_LENGTH);
                    return factory.generateSecret(spec);
                } finally {
                    if (spec != null) {
                        spec.clearPassword();
                    }
                }
            }
        });
    }

    protected byte[] generateInputSalt(KeyRequest<SecretKey, SecretKey> request) {
        byte[] inputSalt = new byte[this.HASH_BYTE_LENGTH];
        ensureSecureRandom(request).nextBytes(inputSalt);
        return inputSalt;
    }

    @Override
    public KeyResult getEncryptionKey(KeyRequest<SecretKey, SecretKey> request) throws SecurityException {

        Assert.notNull(request, "request cannot be null.");
        final SecretKey cek = Assert.notNull(request.getPayload(), "request.getPayload() (content encryption key) cannot be null.");

        SecretKey reqKey = request.getKey();
        Assert.notNull(reqKey, "request.getKey() cannot be null.");
        if (!(reqKey instanceof PBEKey)) {
            String msg = "request.getKey() must be a " + PBEKey.class.getName() + " instance. Type found: " +
                reqKey.getClass().getName();
            throw new IllegalArgumentException(msg);
        }
        final PBEKey pbeKey = (PBEKey) reqKey;
        // we explicitly do not attempt to validate pbeKey.getPassword() at this point because that call will create
        // a clone of the char array, and we'd have to guarantee cleanup of that clone if any failure/exception occurs.
        // Instead, we access the password in only one place - in the execute* method call below - and guarantee
        // cleanup there in a try/finally block

        final int iterations = pbeKey.getIterationCount();
        if (iterations < 1000) {
            String msg = "Password-based encryption password iterations must be >= 1000. Found: " + iterations;
            throw new IllegalArgumentException(msg);
        }

        byte[] inputSalt = generateInputSalt(request);
        final byte[] rfcSalt = Bytes.plus(this.SALT_PREFIX, inputSalt);
        final String p2s = Encoders.BASE64URL.encode(inputSalt);

        final SecretKey derivedKek = deriveKey(request, pbeKey, rfcSalt, iterations);

        // now encrypt (wrap) the CEK with the PBE-derived key:
        DefaultKeyRequest<SecretKey, SecretKey> wrapReq = new DefaultKeyRequest<>(request.getProvider(),
            request.getSecureRandom(), cek, derivedKek, request.getHeader());
        KeyResult result = wrapAlg.getEncryptionKey(wrapReq);

        request.getHeader().put(SALT_HEADER_NAME, p2s);
        request.getHeader().put(ITERATION_HEADER_NAME, iterations);

        return result;
    }

    private static char[] toChars(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        CharBuffer cbuf = StandardCharsets.UTF_8.decode(buf);
        char[] chars = new char[cbuf.limit()];
        cbuf.get(chars);
        return chars;
    }

    private PBEKey toPBEKey(SecretKey key, int iterations) {
        if (key instanceof PBEKey) {
            return (PBEKey) key;
        }
        byte[] keyBytes = null;
        char[] keyChars = null;
        try {
            keyBytes = key.getEncoded();
            keyChars = toChars(keyBytes);
            return new DefaultPBEKey(keyChars, iterations, getId());
        } finally {
            try {
                if (keyChars != null) {
                    java.util.Arrays.fill(keyChars, '\u0000');
                }
            } finally {
                if (keyBytes != null) {
                    java.util.Arrays.fill(keyBytes, (byte) 0);
                }
            }
        }
    }

    @Override
    public SecretKey getDecryptionKey(KeyRequest<byte[], SecretKey> request) throws SecurityException {

        JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        String name = SALT_HEADER_NAME;

        Object value = header.get(name);
        if (value == null) {
            String msg = "The " + getId() + " Key Management Algorithm requires a JweHeader '" + name + "' value.";
            throw new MalformedJwtException(msg);
        }
        if (!(value instanceof String)) {
            String msg = "The " + getId() + " Key Management Algorithm requires the JweHeader '" + name + "' value to be a Base64URL-encoded String. Actual type: " + value.getClass().getName();
            throw new MalformedJwtException(msg);
        }
        String encoded = (String) value;

        final byte[] inputSalt = Decoders.BASE64URL.decode(encoded);
        if (Arrays.length(inputSalt) == 0) {
            String msg = "The " + getId() + " Key Management Algorithm does not support empty JweHeader '" + name + "' values.";
            throw new MalformedJwtException(msg);
        }
        final byte[] rfcSalt = Bytes.plus(SALT_PREFIX, inputSalt);

        name = ITERATION_HEADER_NAME;
        value = header.get(name);
        if (value == null) {
            String msg = "The " + getId() + " Key Management Algorithm requires a JweHeader '" + name + "' value.";
            throw new MalformedJwtException(msg);
        }
        if (!(value instanceof Integer)) {
            String msg = "The " + getId() + " Key Management Algorithm requires the JweHeader '" + name + "' value to be an integer.  Actual type: " + value.getClass().getName();
            throw new MalformedJwtException(msg);
        }
        final int iterations = (Integer) value;
        if (iterations <= 0) {
            String msg = "The " + getId() + " Key Management Algorithm requires the JweHeader '" + name + "' value to be a positive integer.  Actual value: " + iterations;
            throw new MalformedJwtException(msg);
        }

        PBEKey pbeKey = toPBEKey(request.getKey(), iterations);

        final SecretKey derivedKek = deriveKey(request, pbeKey, rfcSalt, iterations);

        KeyRequest<byte[], SecretKey> unwrapReq = new DefaultKeyRequest<>(request.getProvider(),
            request.getSecureRandom(), request.getPayload(), derivedKek, header);

        return wrapAlg.getDecryptionKey(unwrapReq);
    }
}
