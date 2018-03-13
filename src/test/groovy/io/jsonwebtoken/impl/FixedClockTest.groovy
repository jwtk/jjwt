package io.jsonwebtoken.impl

import org.junit.Test
import static org.junit.Assert.*

class FixedClockTest {

    @Test
    void testFixedClockDefaultConstructor() {

        def clock = new FixedClock()

        def now1 = clock.now()
        Thread.sleep(100)
        def now2 = clock.now()

        assertSame now1, now2
    }
}
