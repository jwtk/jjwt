package io.jsonwebtoken.lang;

/**
 * @since 0.6
 */
public final class Arrays {

    private static final Arrays INSTANCE = new Arrays();

    private Arrays(){}

    public static int length(byte[] bytes) {
        return bytes != null ? bytes.length : 0;
    }
}
