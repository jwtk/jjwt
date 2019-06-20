package io.jsonwebtoken.factory


import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull

@RunWith(PowerMockRunner.class)
@PrepareForTest([FactoryLoader])
class FactoryLoaderTest {

    @Test
    void testSuccessfulLoadingOfJwtFactory() {
        def factory = FactoryLoader.loadFactory()

        assertNotNull factory

        assertEquals(TestJwtFactory, factory.class)

        //test coverage for private constructor:
        new FactoryLoader()
    }

    @Test
    void testSuccessfulLoadingOfCompressionCodecFactory() {
        def factory = FactoryLoader.loadCompressionCodecFactory()

        assertNotNull factory

        assertEquals(TestComptressionCodecFactory, factory.class)
    }

    @Test(expected = ImplementationNotFoundException)
    void testFailedLoading() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader()

        Thread.currentThread().setContextClassLoader(new NoServicesClassLoader(cl))

        FactoryLoader.loadFactory()
    }

    static class NoServicesClassLoader extends ClassLoader {
        private NoServicesClassLoader(ClassLoader parent) {
            super(parent)
        }

        @Override
        Enumeration<URL> getResources(String name) throws IOException {
            if(name.startsWith("META-INF/services/")) {
                return Collections.emptyEnumeration()
            } else {
                return super.getResources(name)
            }
        }
    }
}
