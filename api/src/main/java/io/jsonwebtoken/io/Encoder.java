package io.jsonwebtoken.io;

/**
 * @since 0.10.0
 */
public interface Encoder<T, R> {

    R encode(T t) throws EncodingException;
}
