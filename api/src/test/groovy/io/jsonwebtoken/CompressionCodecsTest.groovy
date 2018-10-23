package io.jsonwebtoken

import io.jsonwebtoken.lang.Classes
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.createMock
import static org.easymock.EasyMock.eq
import static org.easymock.EasyMock.expect
import static org.junit.Assert.assertSame
import static org.powermock.api.easymock.PowerMock.mockStatic
import static org.powermock.api.easymock.PowerMock.replay
import static org.powermock.api.easymock.PowerMock.verify

@RunWith(PowerMockRunner.class)
@PrepareForTest([Classes, CompressionCodecs])
class CompressionCodecsTest {

    @Test
    void testStatics() {

        mockStatic(Classes)

        def deflate = createMock(CompressionCodec)
        def gzip = createMock(CompressionCodec)

        expect(Classes.newInstance(eq("io.jsonwebtoken.impl.compression.DeflateCompressionCodec"))).andReturn(deflate)
        expect(Classes.newInstance(eq("io.jsonwebtoken.impl.compression.GzipCompressionCodec"))).andReturn(gzip)

        replay Classes, deflate, gzip

        assertSame deflate, CompressionCodecs.DEFLATE
        assertSame gzip, CompressionCodecs.GZIP

        verify Classes, deflate, gzip

        //test coverage for private constructor:
        new CompressionCodecs()
    }
}
