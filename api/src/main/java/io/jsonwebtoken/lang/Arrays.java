package io.jsonwebtoken.lang;

/**
 * @since 0.6
 */
public final class Arrays {

    private Arrays(){} //prevent instantiation

    public static int length(byte[] bytes) {
        return bytes != null ? bytes.length : 0;
    }

    public static byte[] clean(byte[] bytes) {
        return length(bytes) > 0 ? bytes : null;
    }
}
