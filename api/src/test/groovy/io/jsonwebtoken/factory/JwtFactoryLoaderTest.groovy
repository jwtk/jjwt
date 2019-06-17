package io.jsonwebtoken.factory


import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull

@RunWith(PowerMockRunner.class)
@PrepareForTest([JwtFactoryLoader])
class JwtFactoryLoaderTest {
    @Test
    void testSuccessfulLoading() {
        def factory = JwtFactoryLoader.loadFactory()

        assertNotNull factory

        assertEquals(TestJwtFactory, factory.class)
    }

    @Test(expected = ImplementationNotFoundException)
    void testFailedLoading() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader()

        Thread.currentThread().setContextClassLoader(new NoServicesClassLoader(cl))

        JwtFactoryLoader.loadFactory()
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
