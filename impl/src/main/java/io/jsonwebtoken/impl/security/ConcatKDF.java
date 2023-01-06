/*
 * Copyright (C) 2021 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
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

    /**
     * NIST.SP.800-56Ar2.pdf, Section 5.8.1.1, Input requirement #2 says that the maximum bit length of the
     * derived key cannot be more than this:
     * <code><pre>
     *     hashBitLength * (2^32 - 1)
     * </pre></code>
     * However, this number is always greater than Integer.MAX_VALUE * Byte.SIZE, which is the maximum number of
     * bits that can be represented in a Java byte array.  So our implementation must be limited to that size
     * regardless of what the spec allows:
     */
    private static final long MAX_DERIVED_KEY_BIT_LENGTH = (long) Integer.MAX_VALUE * (long) Byte.SIZE;

    ConcatKDF(String jcaName) {
        super("ConcatKDF", jcaName);
        int hashByteLength = jca().withMessageDigest(new CheckedFunction<MessageDigest, Integer>() {
            @Override
            public Integer apply(MessageDigest instance) {
                return instance.getDigestLength();
            }
        });
        this.hashBitLength = hashByteLength * Byte.SIZE;
        Assert.state(this.hashBitLength > 0, "MessageDigest length must be a positive value.");
    }

    /**
     * 'Clean room' implementation of the Concat KDF algorithm based solely on
     * <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf">NIST.800-56A</a>,
     * Section <code>5.8.1.1</code>.
     *
     * @param Z                   shared secret key to use to seed the derived secret. Cannot be null or empty.
     * @param derivedKeyBitLength the total number of <b>bits</b> <em>(not bytes)</em> required in the returned derived
     *                            key.
     * @param otherInfo           any additional party info to be associated with the derived key. May be null/empty.
     * @return the derived key
     * @throws UnsupportedKeyException if unable to obtain {@code sharedSecretKey}'s
     *                                 {@link Key#getEncoded() encoded byte array}.
     * @throws SecurityException       if unable to perform the necessary {@link MessageDigest} computations to
     *                                 generate the derived key.
     */
    public SecretKey deriveKey(final byte[] Z, final long derivedKeyBitLength, final byte[] otherInfo)
            throws UnsupportedKeyException, SecurityException {

        // sharedSecretKey argument assertions:
        Assert.notEmpty(Z, "Z cannot be null or empty.");

        // derivedKeyBitLength argument assertions:
        Assert.isTrue(derivedKeyBitLength > 0, "derivedKeyBitLength must be a positive integer.");
        if (derivedKeyBitLength > MAX_DERIVED_KEY_BIT_LENGTH) {
            String msg = "derivedKeyBitLength may not exceed " + bitsMsg(MAX_DERIVED_KEY_BIT_LENGTH) +
                    ". Specified size: " + bitsMsg(derivedKeyBitLength) + ".";
            throw new IllegalArgumentException(msg);
        }
        final long derivedKeyByteLength = derivedKeyBitLength / Byte.SIZE;

        final byte[] OtherInfo = otherInfo == null ? EMPTY : otherInfo;

        // Section 5.8.1.1, Process step #1:
        final double repsd = derivedKeyBitLength / (double) this.hashBitLength;
        final long reps = (long) Math.ceil(repsd);
        // If repsd didn't result in a whole number, the last derived key byte will be partially filled per
        // Section 5.8.1.1, Process step #6:
        final boolean kLastPartial = repsd != (double) reps;

        // Section 5.8.1.1, Process step #2:
        Assert.state(reps <= MAX_REP_COUNT, "derivedKeyBitLength is too large.");

        // Section 5.8.1.1, Process step #3:
        final byte[] counter = new byte[]{0, 0, 0, 1}; // same as 0x0001L, but no extra step to convert to byte[]

        // Section 5.8.1.1, Process step #4:
        long inputBitLength = bitLength(counter) + bitLength(Z) + bitLength(OtherInfo);
        Assert.state(inputBitLength <= MAX_HASH_INPUT_BIT_LENGTH, "Hash input is too large.");

        byte[] derivedKeyBytes = jca().withMessageDigest(new CheckedFunction<MessageDigest, byte[]>() {
            @Override
            public byte[] apply(MessageDigest md) throws Exception {

                final ByteArrayOutputStream stream = new ByteArrayOutputStream((int) derivedKeyByteLength);

                // Section 5.8.1.1, Process step #5.  We depart from Java idioms here by starting iteration index at 1
                // (instead of 0) and continue to <= reps (instead of < reps) to match the NIST publication algorithm
                // notation convention (so variables like Ki and kLast below match the NIST definitions).
                for (long i = 1; i <= reps; i++) {

                    // Section 5.8.1.1, Process step #5.1:
                    md.update(counter);
                    md.update(Z);
                    md.update(OtherInfo);
                    byte[] Ki = md.digest();

                    // Section 5.8.1.1, Process step #5.2:
                    increment(counter);

                    // Section 5.8.1.1, Process step #6:
                    if (i == reps && kLastPartial) {
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

        return new SecretKeySpec(derivedKeyBytes, AesAlgorithm.KEY_ALG_NAME);
    }
}
