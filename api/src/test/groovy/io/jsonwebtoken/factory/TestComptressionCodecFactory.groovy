package io.jsonwebtoken.factory

import io.jsonwebtoken.CompressionCodec

class TestComptressionCodecFactory implements CompressionCodecFactory {
    @Override
    CompressionCodec deflateCodec() {
        return null
    }

    @Override
    CompressionCodec gzipCodec() {
        return null
    }
}
