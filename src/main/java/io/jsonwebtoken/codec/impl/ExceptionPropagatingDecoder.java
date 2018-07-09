package io.jsonwebtoken.codec.impl;

import io.jsonwebtoken.codec.Decoder;
import io.jsonwebtoken.codec.DecodingException;
import io.jsonwebtoken.lang.Assert;

public class ExceptionPropagatingDecoder<T, R> implements Decoder<T, R> {

    private final Decoder<T, R> decoder;

    public ExceptionPropagatingDecoder(Decoder<T, R> decoder) {
        Assert.notNull(decoder, "Decoder cannot be null.");
        this.decoder = decoder;
    }

    @Override
    public R decode(T t) throws DecodingException {
        Assert.notNull(t, "Decode argument cannot be null.");
        try {
            return decoder.decode(t);
        } catch (DecodingException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to decode input: " + e.getMessage();
            throw new DecodingException(msg, e);
        }
    }
}
