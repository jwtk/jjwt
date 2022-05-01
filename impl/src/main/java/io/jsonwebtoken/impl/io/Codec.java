package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;

public class Codec implements Converter<byte[], String> {

    public static final Codec BASE64 = new Codec(Encoders.BASE64, Decoders.BASE64);
    public static final Codec BASE64URL = new Codec(Encoders.BASE64URL, Decoders.BASE64URL);

    private final Encoder<byte[], String> encoder;
    private final Decoder<String, byte[]> decoder;

    public Codec(Encoder<byte[], String> encoder, Decoder<String, byte[]> decoder) {
        this.encoder = Assert.notNull(encoder, "Encoder cannot be null.");
        this.decoder = Assert.notNull(decoder, "Decoder cannot be null.");
    }

    @Override
    public String applyTo(byte[] a) {
        return this.encoder.encode(a);
    }

    @Override
    public byte[] applyFrom(String b) {
        try {
            return this.decoder.decode(b);
        } catch (DecodingException e) {
            String msg = "Cannot decode input String. Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
    }
}
