package io.jsonwebtoken

import io.jsonwebtoken.factory.CompressionCodecFactory
import io.jsonwebtoken.factory.FactoryLoader
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.expect
import static org.junit.Assert.assertSame
import static org.powermock.api.easymock.PowerMock.*

@RunWith(PowerMockRunner.class)
@PrepareForTest([FactoryLoader, CompressionCodecs])
class CompressionCodecsTest {

    @Test
    void testStatics() {

        mockStatic(FactoryLoader)

        def factory = createMock(CompressionCodecFactory)

        expect(FactoryLoader.loadCompressionCodecFactory()).andReturn(factory)

        def deflate = createMock(CompressionCodec)
        def gzip = createMock(CompressionCodec)

        expect(factory.deflateCodec()).andReturn(deflate)
        expect(factory.gzipCodec()).andReturn(gzip)

        replay FactoryLoader, factory, deflate, gzip

        assertSame deflate, CompressionCodecs.DEFLATE
        assertSame gzip, CompressionCodecs.GZIP

        verify FactoryLoader, factory, deflate, gzip

        //test coverage for private constructor:
        new CompressionCodecs()
    }
}
