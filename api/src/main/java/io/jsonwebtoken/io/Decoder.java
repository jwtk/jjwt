package io.jsonwebtoken.io;

/**
 * @since 0.10.0
 */
public interface Decoder<T, R> {

    R decode(T t) throws DecodingException;
}
