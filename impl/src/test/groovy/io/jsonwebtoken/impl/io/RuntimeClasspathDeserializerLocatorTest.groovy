package io.jsonwebtoken.impl.io

import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.JacksonDeserializer
import io.jsonwebtoken.io.OrgJsonDeserializer
import org.junit.After
import org.junit.Before
import org.junit.Test

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class RuntimeClasspathDeserializerLocatorTest {

    private static final String TEST_SERVICE_DESCRIPTOR = "io.jsonwebtoken.io.Deserializer.test.orgjson"

    private ClassLoader originalClassLoader

    @Before
    void setUp() {
        RuntimeClasspathDeserializerLocator.DESERIALIZER.set(null)
    }

    @After
    void teardown() {
        RuntimeClasspathDeserializerLocator.DESERIALIZER.set(null)
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
            new RuntimeClasspathDeserializerLocator().getInstance()
            fail 'Located Deserializer class, whereas none was expected.'
        } catch (Exception ex) {
            assertEquals 'Unable to discover any JSON Deserializer implementations on the classpath.', ex.message
        }
    }

    @Test
    void testCompareAndSetFalse() {
        Deserializer deserializer = createMock(Deserializer)
        def locator = new RuntimeClasspathDeserializerLocator() {
            @Override
            protected boolean compareAndSet(Deserializer d) {
                RuntimeClasspathDeserializerLocator.DESERIALIZER.set(deserializer)
                return false
            }
        }

        def returned = locator.getInstance()
        assertSame deserializer, returned
    }

    @Test(expected = IllegalStateException)
    void testLocateReturnsNull() {
        def locator = new RuntimeClasspathDeserializerLocator() {
            @Override
            protected Deserializer locate() {
                return null
            }
        }
        locator.getInstance()
    }

    @Test(expected = IllegalStateException)
    void testCompareAndSetFalseWithNullReturn() {
        def locator = new RuntimeClasspathDeserializerLocator() {
            @Override
            protected boolean compareAndSet(Deserializer d) {
                return false
            }
        }
        locator.getInstance()
    }

    @Test
    void testJackson() {
        def deserializer = new RuntimeClasspathDeserializerLocator().getInstance()
        assertTrue deserializer instanceof JacksonDeserializer
    }

    @Test
    void testOrgJson() {
        prepareFakeServiceClassLoader()

        def deserializer = new RuntimeClasspathDeserializerLocator().getInstance()
        assertTrue deserializer instanceof OrgJsonDeserializer
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
