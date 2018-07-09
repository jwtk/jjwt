package io.jsonwebtoken.codec;

import io.jsonwebtoken.codec.impl.Base64Decoder;
import io.jsonwebtoken.codec.impl.Base64UrlDecoder;
import io.jsonwebtoken.codec.impl.ExceptionPropagatingDecoder;

/**
 * @param <T>
 * @param <R>
 * @since 0.10.0
 */
public interface Decoder<T, R> {

    Decoder<String, byte[]> BASE64 = new ExceptionPropagatingDecoder<>(new Base64Decoder());
    Decoder<String, byte[]> BASE64URL = new ExceptionPropagatingDecoder<>(new Base64UrlDecoder());

    R decode(T t) throws DecodingException;
}
