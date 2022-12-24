package io.jsonwebtoken.impl.security


import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class DefaultCurveTest {

    DefaultCurve curve

    @Before
    void setUp() {
        curve = new DefaultCurve('foo', 'bar')
    }

    @Test
    void testGetId() {
        assertEquals 'foo', curve.getId()
    }

    @Test
    void testGetJcaName() {
        assertEquals 'bar', curve.getJcaName()
    }

    @Test
    void testHashcode() {
        assertEquals 'foo'.hashCode(), curve.hashCode()
    }

    @Test
    void testToString() {
        assertEquals 'foo', curve.toString()
    }

    @Test
    void testEqualsIdentity() {
        //noinspection ChangeToOperator
        assertTrue curve.equals(curve)
    }

    @Test
    void testEqualsTypeMismatch() {
        Object obj = new Integer(42)
        //noinspection ChangeToOperator
        assertFalse curve.equals(obj);
    }

    @Test
    void testEqualsId() {
        def other = new DefaultCurve('foo', 'asdfasdf')
        //noinspection ChangeToOperator
        assertTrue curve.equals(other)
    }

    @Test
    void testNotEquals() {
        def other = new DefaultCurve('abc', 'bar')
        //noinspection ChangeToOperator
        assertFalse curve.equals(other)
    }

    @Test
    void testKeyPairBuilder() {
        def builder = curve.keyPairBuilder()
        assertEquals 'bar', builder.jcaName //builder is an instanceof DefaultKeyPairBuilder
    }
}
