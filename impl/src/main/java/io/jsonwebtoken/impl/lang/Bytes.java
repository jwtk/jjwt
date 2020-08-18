package io.jsonwebtoken.impl.lang;

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
            ((bytes[7] & 0xFFL));
    }

    public static int toInt(byte[] bytes) {
        Assert.isTrue(Arrays.length(bytes) == INT_BYTE_LENGTH, INT_REQD_MSG);
        return ((bytes[0] & 0xFF) << 24) |
            ((bytes[1] & 0xFF) << 16) |
            ((bytes[2] & 0xFF) << 8) |
            (bytes[3] & 0xFF);
    }

    public static int[] toInts(byte[] bytes) {
        int[] ints = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            ints[i] = bytes[i] & 0xFF;
        }
        return ints;
    }

    public static byte[] concat(byte[]... arrays) {
        int len = 0;
        int count = Arrays.length(arrays);
        for (int i = 0; i < count; i++) {
            len += arrays[i].length;
        }
        byte[] output = new byte[len];
        int position = 0;
        if (len > 0) {
            for (byte[] array : arrays) {
                int alen = Arrays.length(array);
                if (alen > 0) {
                    System.arraycopy(array, 0, output, position, alen);
                    position += alen;
                }
            }
        }
        return output;
    }

    public static int byteLength(byte[] bytes) {
        return bytes == null ? 0 : bytes.length;
    }

    public static long bitLength(byte[] bytes) {
        return bytes == null ? 0 : bytes.length * (long) Byte.SIZE;
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
