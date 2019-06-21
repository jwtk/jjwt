package io.jsonwebtoken.impl;

import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.CompressionCodecFactory;
import io.jsonwebtoken.impl.compression.DeflateCompressionCodec;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;

public class DefaultCompressionCodecFactory implements CompressionCodecFactory {
    @Override
    public CompressionCodec deflateCodec() {
        return new DeflateCompressionCodec();
    }

    @Override
    public CompressionCodec gzipCodec() {
        return new GzipCompressionCodec();
    }
}
