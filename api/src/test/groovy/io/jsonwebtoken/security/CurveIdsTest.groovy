package io.jsonwebtoken.security

import org.junit.Test
import static org.junit.Assert.*

class CurveIdsTest {

    @Test(expected=IllegalArgumentException)
    void testNullId() {
        CurveIds.forValue(null)
    }

    @Test(expected=IllegalArgumentException)
    void testEmptyId() {
        CurveIds.forValue(' ')
    }

    @Test
    void testNonStandardId() {
        CurveId id = CurveIds.forValue("NonStandard")
        assertNotNull id
        assertEquals 'NonStandard', id.toString()
    }
}
