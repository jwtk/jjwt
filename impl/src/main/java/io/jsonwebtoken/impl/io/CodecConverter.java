package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;

public class CodecConverter<A, B> implements Converter<A, B> {

    public static final CodecConverter<byte[], String> BASE64 = new CodecConverter<>(Encoders.BASE64, Decoders.BASE64);
    public static final CodecConverter<byte[], String> BASE64URL = new CodecConverter<>(Encoders.BASE64URL, Decoders.BASE64URL);

    private final Encoder<A, B> encoder;
    private final Decoder<B, A> decoder;

    public CodecConverter(Encoder<A, B> encoder, Decoder<B, A> decoder) {
        this.encoder = Assert.notNull(encoder, "Encoder cannot be null.");
        this.decoder = Assert.notNull(decoder, "Decoder cannot be null.");
    }

    @Override
    public B applyTo(A a) {
        return this.encoder.encode(a);
    }

    @Override
    public A applyFrom(B b) {
        return this.decoder.decode(b);
    }
}
