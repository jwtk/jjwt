package io.jsonwebtoken.impl.io

import org.junit.Test

import java.util.concurrent.Callable

import static org.junit.Assert.*

class StreamsTest {

    @Test
    void runWrapsExceptionAsRuntimeIOException() {
        def ex = new RuntimeException('foo')
        def c = new Callable() {
            @Override
            Object call() throws Exception {
                throw ex
            }
        }
        try {
            Streams.run(c, 'bar')
            fail()
        } catch (io.jsonwebtoken.io.IOException expected) {
            String msg = 'bar'
            assertEquals msg, expected.message
            assertSame ex, expected.cause
        }
    }
}
