package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.UnsupportedKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.MessageDigest;

import static io.jsonwebtoken.impl.lang.Bytes.*;

/**
 * 'Clean room' implementation of the Concat KDF algorithm based solely on
 * <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf">NIST.800-56A</a>,
 * Section <code>5.8.1.1</code>.  Call the {@link #deriveKey(byte[], long, byte[]) deriveKey} method.
 */
final class ConcatKDF extends CryptoAlgorithm {

    private static final long MAX_REP_COUNT = 0xFFFFFFFFL;
    private static final long MAX_HASH_INPUT_BYTE_LENGTH = Integer.MAX_VALUE; //no Java byte arrays bigger than this
    private static final long MAX_HASH_INPUT_BIT_LENGTH = MAX_HASH_INPUT_BYTE_LENGTH * Byte.SIZE;

    private final int hashBitLength;
    private final long MAX_DERIVED_KEY_BIT_LENGTH;

    ConcatKDF(String jcaName) {
        super("ConcatKDF", jcaName);
        int hashByteLength = execute(MessageDigest.class, new CheckedFunction<MessageDigest, Integer>() {
            @Override
            public Integer apply(MessageDigest instance) {
                return instance.getDigestLength();
            }
        });
        this.hashBitLength = hashByteLength * Byte.SIZE;
        assert this.hashBitLength > 0 : "MessageDigest length must be a positive value.";
        MAX_DERIVED_KEY_BIT_LENGTH = this.hashBitLength * MAX_REP_COUNT;
    }

    /**
     * 'Clean room' implementation of the Concat KDF algorithm based solely on
     * <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf">NIST.800-56A</a>,
     * Section <code>5.8.1.1</code>.
     *
     * @param Z                   shared secret key to use to seed the derived secret. Cannot be null or empty.
     * @param derivedKeyBitLength the total number of <b>bits</b> <em>(not bytes)</em> required in the returned derived
     *                            key.
     * @param OtherInfo           any additional party info to be associated with the derived key. May be null/empty.
     * @return the derived key
     * @throws UnsupportedKeyException if unable to obtain {@code sharedSecretKey}'s
     *                                 {@link Key#getEncoded() encoded byte array}.
     * @throws SecurityException       if unable to perform the necessary {@link MessageDigest} computations to
     *                                 generate the derived key.
     */
    public SecretKey deriveKey(final byte[] Z, final long derivedKeyBitLength, final byte[] OtherInfo)
        throws UnsupportedKeyException, SecurityException {

        // OtherInfo argument assertions:
        final int otherInfoByteLength = Arrays.length(OtherInfo);

        // sharedSecretKey argument assertions:
        Assert.notEmpty(Z, "Z cannot be null or empty.");

        // derivedKeyBitLength argument assertions:
        Assert.isTrue(derivedKeyBitLength > 0, "derivedKeyBitLength must be a positive number.");
        final long derivedKeyByteLength = derivedKeyBitLength / Byte.SIZE;
        if (derivedKeyByteLength > Integer.MAX_VALUE) { // Java byte arrays can't be bigger than this
            throw new IllegalArgumentException("derivedKeyBitLength cannot reflect a byte array size greater than Integer.MAX_VALUE.");
        }
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf, Section 5.8.1.1, Input requirement #2:
        if (derivedKeyBitLength > MAX_DERIVED_KEY_BIT_LENGTH) {
            String msg = "derivedKeyBitLength for " + getJcaName() + "-derived keys may not exceed " +
                bitsMsg(MAX_DERIVED_KEY_BIT_LENGTH) + ".  Specified size: " + bitsMsg(derivedKeyBitLength) + ".";
            throw new IllegalArgumentException(msg);
        }

        // Section 5.8.1.1, Process step #1:
        final double repsd = derivedKeyBitLength / (double) this.hashBitLength;
        final long reps = (long) (Math.ceil(repsd));

        // Section 5.8.1.1, Process step #2:
        assert reps <= MAX_REP_COUNT : "derivedKeyBitLength is too large.";

        // Section 5.8.1.1, Process step #3:
        final byte[] counter = new byte[]{0, 0, 0, 1}; // same as 0x0001L, but no extra step to convert to byte[]

        // Section 5.8.1.1, Process step #4:
        long inputBitLength = bitLength(counter) + bitLength(Z) + bitLength(OtherInfo);
        assert inputBitLength <= MAX_HASH_INPUT_BIT_LENGTH : "Hash input is too large.";

        byte[] derivedKeyBytes = new JcaTemplate(getJcaName(), null).execute(MessageDigest.class, new CheckedFunction<MessageDigest, byte[]>() {
            @Override
            public byte[] apply(MessageDigest md) throws Exception {

                final ByteArrayOutputStream stream = new ByteArrayOutputStream((int) derivedKeyByteLength);
                long kLastIndex = reps - 1;

                // Section 5.8.1.1, Process step #5:
                for (long i = 0; i < reps; i++) {

                    // Section 5.8.1.1, Process step #5.1:
                    md.update(counter);
                    md.update(Z);
                    if (otherInfoByteLength > 0) {
                        md.update(OtherInfo);
                    }
                    byte[] Ki = md.digest();

                    // Section 5.8.1.1, Process step #5.2:
                    increment(counter);

                    // Section 5.8.1.1, Process step #6:
                    if (i == kLastIndex && repsd != (double) reps) { //repsd calculation above didn't result in a whole number:
                        long leftmostBitLength = derivedKeyBitLength % hashBitLength;
                        int leftmostByteLength = (int) (leftmostBitLength / Byte.SIZE);
                        byte[] kLast = new byte[leftmostByteLength];
                        System.arraycopy(Ki, 0, kLast, 0, kLast.length);
                        Ki = kLast;
                    }

                    stream.write(Ki);
                }

                // Section 5.8.1.1, Process step #7:
                return stream.toByteArray();
            }
        });

        return new SecretKeySpec(derivedKeyBytes, "AES");
    }
}
