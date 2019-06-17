package io.jsonwebtoken.impl

import io.jsonwebtoken.impl.DefaultCompressionCodecFactory
import io.jsonwebtoken.impl.compression.DeflateCompressionCodec
import io.jsonwebtoken.impl.compression.GzipCompressionCodec
import org.junit.Test

import static org.junit.Assert.assertEquals

class DefaultCompressionCodecFactoryTest {
    @Test
    void testCreateDeflateCodec() {

        def deflate = new DefaultCompressionCodecFactory().deflateCodec()

        assertEquals(DeflateCompressionCodec, deflate.class)
    }

    @Test
    void testCreateGzipCodec() {

        def gzipCodec = new DefaultCompressionCodecFactory().gzipCodec()

        assertEquals(GzipCompressionCodec, gzipCodec.class)
    }
}
