package io.jsonwebtoken.codec.impl;

import io.jsonwebtoken.codec.Encoder;
import io.jsonwebtoken.codec.EncodingException;
import io.jsonwebtoken.lang.Assert;

public class ExceptionPropagatingEncoder<T,R> implements Encoder<T,R> {

    private final Encoder<T,R> encoder;

    public ExceptionPropagatingEncoder(Encoder<T,R> encoder) {
        Assert.notNull(encoder, "Encoder cannot be null.");
        this.encoder = encoder;
    }

    @Override
    public R encode(T t) throws EncodingException {
        Assert.notNull(t, "Encode argument cannot be null.");
        try {
            return this.encoder.encode(t);
        } catch (EncodingException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to encode input: " + e.getMessage();
            throw new EncodingException(msg, e);
        }
    }
}
