package io.jsonwebtoken.codec;

import io.jsonwebtoken.codec.impl.Base64Encoder;
import io.jsonwebtoken.codec.impl.Base64UrlEncoder;
import io.jsonwebtoken.codec.impl.ExceptionPropagatingEncoder;

/**
 * @param <T>
 * @param <R>
 * @since 0.10.0
 */
public interface Encoder<T, R> {

    Encoder<byte[], String> BASE64 = new ExceptionPropagatingEncoder<>(new Base64Encoder());
    Encoder<byte[], String> BASE64URL = new ExceptionPropagatingEncoder<>(new Base64UrlEncoder());

    R encode(T t) throws EncodingException;

}
