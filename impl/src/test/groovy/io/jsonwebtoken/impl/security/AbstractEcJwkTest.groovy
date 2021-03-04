package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.CurveId
import io.jsonwebtoken.security.CurveIds
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test
import static org.junit.Assert.*

class AbstractEcJwkTest {

    class TestEcJwk extends AbstractEcJwk {
    }

    @Test
    void testType() {
        assertEquals 'EC', new TestEcJwk().getType()
    }

    @Test
    void testSetNullX() {
        try {
            new TestEcJwk().setX(null)
            fail()
        } catch (IllegalArgumentException e) {
            assertEquals "EC JWK x coordinate ('x' property) cannot be null.", e.getMessage()
        }
    }

    @Test
    void testSetEmptyX() {
        try {
            new TestEcJwk().setX(' ')
            fail()
        } catch (IllegalArgumentException e) {
            assertEquals "EC JWK x coordinate ('x' property) cannot be null or empty.", e.getMessage()
        }
    }

    @Test
    void testX() {
        def jwk = new TestEcJwk()
        assertEquals 'x', AbstractEcJwk.X
        String val = UUID.randomUUID().toString()
        jwk.setX(val)
        assertEquals val, jwk.get(AbstractEcJwk.X)
        assertEquals val, jwk.getX()
    }

    @Test
    void testY() {
        def jwk = new TestEcJwk()
        assertEquals 'y', AbstractEcJwk.Y

        jwk.setY(null) //is allowed to be null for non-standard curves
        assertNull jwk.get(AbstractEcJwk.Y)
        assertNull jwk.getY()

        jwk.setY(' ')
        assertNull jwk.get(AbstractEcJwk.Y)
        assertNull jwk.getY()

        String val = UUID.randomUUID().toString()
        jwk.setY(val)
        assertEquals val, jwk.get(AbstractEcJwk.Y)
        assertEquals val, jwk.getY()
    }

    @Test
    void testSetNullCurveId() {
        try {
            new TestEcJwk().setCurveId(null)
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals "EC JWK curve id ('crv' property) cannot be null.", iae.getMessage()
        }
    }

    @Test
    void testCurveId() {
        def jwk = new TestEcJwk()
        assertEquals 'crv', AbstractEcJwk.CURVE_ID
        assertNull jwk.getCurveId()

        for(CurveId id : CurveIds.values()) {
            jwk.setCurveId(id)
            assertEquals id, jwk.get(AbstractEcJwk.CURVE_ID)
            assertEquals id, jwk.getCurveId()
            jwk.remove(AbstractEcJwk.CURVE_ID)
        }

        //assert string conversion works:
        for(CurveId id : CurveIds.values()) {
            String sval = id.toString()
            jwk.put(AbstractEcJwk.CURVE_ID, sval)
            CurveId returned = jwk.getCurveId()
            assertEquals id, returned
            assertEquals id, jwk.get(AbstractEcJwk.CURVE_ID) //ensure conversion occurred
        }
    }

    @Test
    void testGetCurveIdWithInvalidValueType() {

        def jwk = new TestEcJwk()

        def val = new Integer(5)
        jwk.put(AbstractEcJwk.CURVE_ID, val)

        try {
            jwk.getCurveId()
            fail()
        } catch (MalformedKeyException e) {
            assertEquals "EC JWK 'crv' value must be an CurveId or a String. Value has type: " + val.getClass().getName(), e.getMessage()
        }
    }
}
