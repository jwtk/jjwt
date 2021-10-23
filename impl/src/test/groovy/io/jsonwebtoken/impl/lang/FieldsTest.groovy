package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertFalse

class FieldsTest {

    @Test
    void testPrivateCtor() { // for code coverage only
        new Fields()
    }

    @Test
    void testString() {
        def field = Fields.builder(String.class).setId('foo').setName("FooName").build()
        assertEquals 'FooName', field.getName()
        assertEquals 'foo', field.getId()
        assertEquals String.class, field.getIdiomaticType()
    }

    @Test
    void testEquals() {
        def a = Fields.string('foo', "NameA")
        def b = Fields.builder(Object.class).setId('foo').setName("NameB").build()
        //ensure equality only based on id:
        assertEquals a, b
    }

    @Test
    void testHashCode() {
        def a = Fields.string('foo', "NameA")
        def b = Fields.builder(Object.class).setId('foo').setName("NameB").build()
        //ensure only based on id:
        assertEquals a.hashCode(), b.hashCode()
    }

    @Test
    void testToString() {
        assertEquals "'foo' (FooName)", Fields.string('foo', 'FooName').toString()
    }

    @Test
    void testEqualsNonField() {
        def field = Fields.builder(String.class).setId('foo').setName("FooName").build()
        assertFalse field.equals(new Object())
    }
}
