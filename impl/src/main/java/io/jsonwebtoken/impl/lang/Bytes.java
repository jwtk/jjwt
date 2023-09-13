/*
 * Copyright © 2020 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.impl.security.Randoms;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;

public final class Bytes {

    public static final byte[] EMPTY = new byte[0];

    private static final int LONG_BYTE_LENGTH = Long.SIZE / Byte.SIZE;
    private static final int INT_BYTE_LENGTH = Integer.SIZE / Byte.SIZE;
    public static final String LONG_REQD_MSG = "Long byte arrays must be " + LONG_BYTE_LENGTH + " bytes in length.";
    public static final String INT_REQD_MSG = "Integer byte arrays must be " + INT_BYTE_LENGTH + " bytes in length.";

    //prevent instantiation
    private Bytes() {
    }

    public static byte[] randomBits(int numBits) {
        return random(numBits / Byte.SIZE);
    }

    public static byte[] random(int numBytes) {
        if (numBytes <= 0) {
            throw new IllegalArgumentException("numBytes argument must be >= 0");
        }
        byte[] bytes = new byte[numBytes];
        Randoms.secureRandom().nextBytes(bytes);
        return bytes;
    }

    public static byte[] toBytes(int i) {
        return new byte[]{
                (byte) (i >>> 24),
                (byte) (i >>> 16),
                (byte) (i >>> 8),
                (byte) i
        };
    }

    public static byte[] toBytes(long l) {
        return new byte[]{
                (byte) (l >>> 56),
                (byte) (l >>> 48),
                (byte) (l >>> 40),
                (byte) (l >>> 32),
                (byte) (l >>> 24),
                (byte) (l >>> 16),
                (byte) (l >>> 8),
                (byte) l
        };
    }

    public static long toLong(byte[] bytes) {
        Assert.isTrue(Arrays.length(bytes) == LONG_BYTE_LENGTH, LONG_REQD_MSG);
        return ((bytes[0] & 0xFFL) << 56) |
                ((bytes[1] & 0xFFL) << 48) |
                ((bytes[2] & 0xFFL) << 40) |
                ((bytes[3] & 0xFFL) << 32) |
                ((bytes[4] & 0xFFL) << 24) |
                ((bytes[5] & 0xFFL) << 16) |
                ((bytes[6] & 0xFFL) << 8) |
                (bytes[7] & 0xFFL);
    }

    public static int toInt(byte[] bytes) {
        Assert.isTrue(Arrays.length(bytes) == INT_BYTE_LENGTH, INT_REQD_MSG);
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }

    public static int indexOf(byte[] source, byte[] target) {
        return indexOf(source, target, 0);
    }

    public static int indexOf(byte[] source, byte[] target, int fromIndex) {
        return indexOf(source, 0, length(source), target, 0, length(target), fromIndex);
    }


    static int indexOf(byte[] source, int srcOffset, int srcLen,
                       byte[] target, int targetOffset, int targetLen,
                       int fromIndex) {

        if (fromIndex >= srcLen) {
            return (targetLen == 0 ? srcLen : -1);
        }
        if (fromIndex < 0) {
            fromIndex = 0;
        }
        if (targetLen == 0) {
            return fromIndex;
        }

        byte first = target[targetOffset];
        int max = srcOffset + (srcLen - targetLen);

        for (int i = srcOffset + fromIndex; i <= max; i++) { //

            if (source[i] != first) { // continue on to find the first matching byte
                //noinspection StatementWithEmptyBody
                while (++i <= max && source[i] != first) ;
            }

            if (i <= max) { // found first byte in target, now try to find the rest:
                int j = i + 1;
                int end = j + targetLen - 1;
                //noinspection StatementWithEmptyBody
                for (int k = targetOffset + 1; j < end && source[j] == target[k]; j++, k++) ;
                if (j == end) {
                    return i - srcOffset; // found entire target byte array
                }
            }
        }
        return -1;
    }

    public static boolean startsWith(byte[] src, byte[] prefix) {
        return startsWith(src, prefix, 0);
    }

    public static boolean startsWith(byte[] src, byte[] prefix, int offset) {
        int to = offset;
        int po = 0;
        int pc = length(prefix);
        if ((offset < 0) || (offset > length(src) - pc)) {
            return false;
        }
        while (--pc >= 0) {
            if (src[to++] != prefix[po++]) {
                return false;
            }
        }
        return true;
    }

    public static boolean endsWith(byte[] src, byte[] suffix) {
        return startsWith(src, suffix, length(src) - length(suffix));
    }

    public static byte[] concat(byte[]... arrays) {
        int len = 0;
        int numArrays = Arrays.length(arrays);
        for (int i = 0; i < numArrays; i++) {
            len += length(arrays[i]);
        }
        byte[] output = new byte[len];
        int position = 0;
        if (len > 0) {
            for (byte[] array : arrays) {
                int alen = length(array);
                if (alen > 0) {
                    System.arraycopy(array, 0, output, position, alen);
                    position += alen;
                }
            }
        }
        return output;
    }

    /**
     * Clears the array by filling it with all zeros. Does nothing with a null or empty argument.
     *
     * @param bytes the (possibly null or empty) byte array to clear
     */
    public static void clear(byte[] bytes) {
        if (isEmpty(bytes)) return;
        java.util.Arrays.fill(bytes, (byte) 0);
    }

    public static boolean isEmpty(byte[] bytes) {
        return length(bytes) == 0;
    }

    public static int length(byte[] bytes) {
        return bytes == null ? 0 : bytes.length;
    }

    public static long bitLength(byte[] bytes) {
        return length(bytes) * (long) Byte.SIZE;
    }

    /**
     * Returns the minimum number of bytes required to represent the specified number of bits.
     *
     * <p>This is defined/used by many specifications, such as:</p>
     * <ul>
     *     <li><a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-2">JWA RFC 7518, Section 2</a>'s
     *     <code>Base64urlUInt</code> definition</li>
     *     <li>Elliptic Curve <code>Integer-to-OctetString</code> conversion defined by Section 2.3.7 of the
     *     <a href="http://www.secg.org/sec1-v2.pdf">Standards for Efficient Cryptography Group,
     *     &qupt;SEC 1: Elliptic Curve Cryptography&quot; Version 2.0, May 2009</a> (as required by
     *     <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a>)</li>
     *     <li>and others.</li>
     * </ul>
     *
     * @param bitLength the number of bits to represent as a byte array, must be >= 0
     * @return the minimum number of bytes required to represent the specified number of bits.
     * @throws IllegalArgumentException if {@code bitLength} is less than zero.
     */
    public static int length(int bitLength) {
        if (bitLength < 0) throw new IllegalArgumentException("bitLength argument must be >= 0");
        return (bitLength + 7) / Byte.SIZE;
    }

    public static String bitsMsg(long bitLength) {
        return bitLength + " bits (" + bitLength / Byte.SIZE + " bytes)";
    }

    public static String bytesMsg(int byteArrayLength) {
        return bitsMsg((long) byteArrayLength * Byte.SIZE);
    }

    public static void increment(byte[] a) {
        for (int i = a.length - 1; i >= 0; --i) {
            if (++a[i] != 0) {
                break;
            }
        }
    }
}
