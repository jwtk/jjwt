package io.jsonwebtoken.impl.io

import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.io.JacksonSerializer
import io.jsonwebtoken.io.OrgJsonSerializer
import org.junit.After
import org.junit.Before
import org.junit.Test

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class RuntimeClasspathSerializerLocatorTest {

    private static final String TEST_SERVICE_DESCRIPTOR = "io.jsonwebtoken.io.Serializer.test.orgjson"

    private ClassLoader originalClassLoader

    @Before
    void setUp() {
        RuntimeClasspathSerializerLocator.SERIALIZER.set(null)
    }

    @After
    void teardown() {
        RuntimeClasspathSerializerLocator.SERIALIZER.set(null)
        restoreOriginalClassLoader()
    }

    private void restoreOriginalClassLoader() {
        if(originalClassLoader != null) {
            Thread.currentThread().setContextClassLoader(originalClassLoader)
            originalClassLoader = null
        }
    }

    @Test
    void testClassIsNotAvailable() {
        prepareNoServiceDescriptorClassLoader()

        try {
            new RuntimeClasspathSerializerLocator().getInstance()
            fail 'Located Deserializer class, whereas none was expected.'
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
        prepareFakeServiceClassLoader()

        def serializer = new RuntimeClasspathSerializerLocator().getInstance()
        assertTrue serializer instanceof OrgJsonSerializer
    }

    private void prepareNoServiceDescriptorClassLoader() {
        originalClassLoader = Thread.currentThread().getContextClassLoader()
        Thread.currentThread().setContextClassLoader(new NoServiceDescriptorClassLoader(originalClassLoader))
    }

    private void prepareFakeServiceClassLoader() {
        originalClassLoader = Thread.currentThread().getContextClassLoader()
        Thread.currentThread().setContextClassLoader(new FakeServiceDescriptorClassLoader(originalClassLoader, TEST_SERVICE_DESCRIPTOR))
    }
}
