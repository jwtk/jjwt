package io.jsonwebtoken.io.impl

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.io.impl.jackson.JacksonSerializer
import io.jsonwebtoken.io.impl.orgjson.OrgJsonSerializer
import org.junit.After
import org.junit.Before
import org.junit.Test

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class RuntimeClasspathSerializerLocatorTest {

    @Before
    void setUp() {
        RuntimeClasspathSerializerLocator.SERIALIZER.set(null)
    }

    @After
    void teardown() {
        RuntimeClasspathSerializerLocator.SERIALIZER.set(null)
    }

    @Test
    void testClassIsNotAvailable() {
        def locator = new RuntimeClasspathSerializerLocator() {
            @Override
            protected boolean isAvailable(String fqcn) {
                return false
            }
        }
        try {
            locator.getInstance()
        } catch (Exception ex) {
            assertEquals 'Unable to discover any JSON Serializer implementations on the classpath.', ex.message
        }
    }

    @Test
    void testCompareAndSetFalse() {
        Serializer serializer = createMock(Serializer)
        def locator = new RuntimeClasspathSerializerLocator() {
            @Override
            protected boolean compareAndSet(Serializer s) {
                RuntimeClasspathSerializerLocator.SERIALIZER.set(serializer)
                return false
            }
        }

        def returned = locator.getInstance()
        assertSame serializer, returned
    }

    @Test(expected = IllegalStateException)
    void testLocateReturnsNull() {
        def locator = new RuntimeClasspathSerializerLocator() {
            @Override
            protected Serializer<Object> locate() {
                return null
            }
        }
        locator.getInstance()
    }

    @Test(expected = IllegalStateException)
    void testCompareAndSetFalseWithNullReturn() {
        def locator = new RuntimeClasspathSerializerLocator() {
            @Override
            protected boolean compareAndSet(Serializer<Object> s) {
                return false
            }
        }
        locator.getInstance()
    }

    @Test
    void testJackson() {
        def serializer = new RuntimeClasspathSerializerLocator().getInstance()
        assertTrue serializer instanceof JacksonSerializer
    }

    @Test
    void testOrgJson() {
        def locator = new RuntimeClasspathSerializerLocator() {
            @Override
            protected boolean isAvailable(String fqcn) {
                if (ObjectMapper.class.getName().equals(fqcn)) {
                    return false //skip it to allow the OrgJson impl to be created
                }
                return super.isAvailable(fqcn)
            }
        }

        def serializer = locator.getInstance()
        assertTrue serializer instanceof OrgJsonSerializer
    }
}
