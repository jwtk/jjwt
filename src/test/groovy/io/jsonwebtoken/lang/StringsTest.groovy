package io.jsonwebtoken.lang

import org.junit.Test

import static org.junit.Assert.*

class StringsTest {

    @Test
    void testHasText() {
        assertFalse Strings.hasText(null)
        assertFalse Strings.hasText("")
        assertFalse Strings.hasText("   ")
        assertTrue Strings.hasText("  foo   ");
        assertTrue Strings.hasText("foo")
    }
    
    @Test
    void testClean() {
        assertEquals "this is a test", Strings.clean("this is a test")
        assertEquals "this is a test", Strings.clean("   this is a test")
        assertEquals "this is a test", Strings.clean("   this is a test   ")
        assertEquals "this is a test", Strings.clean("\nthis is a test \t  ")
        assertNull Strings.clean(null)
        assertNull Strings.clean("")
        assertNull Strings.clean("\t")
        assertNull Strings.clean("      ")
    }
    
    @Test
    void testCleanCharSequence() {
    	def result = Strings.clean(new StringBuilder("this is a test"))
    	assertNotNull result
        assertEquals "this is a test", result.toString()
        
        result = Strings.clean(new StringBuilder("   this is a test"))
    	assertNotNull result
        assertEquals "this is a test", result.toString()
        
        result = Strings.clean(new StringBuilder("   this is a test   "))
    	assertNotNull result
        assertEquals "this is a test", result.toString()
        
        result = Strings.clean(new StringBuilder("\nthis is a test \t  "))
    	assertNotNull result
        assertEquals "this is a test", result.toString()
        
        assertNull Strings.clean((StringBuilder) null)
        assertNull Strings.clean(new StringBuilder(""))
        assertNull Strings.clean(new StringBuilder("\t"))
        assertNull Strings.clean(new StringBuilder("      "))
    }
    
    
    @Test
    void testTrimWhitespace() {
    	assertEquals "", Strings.trimWhitespace("      ")
    }
}
