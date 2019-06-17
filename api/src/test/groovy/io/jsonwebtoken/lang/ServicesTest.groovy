package io.jsonwebtoken.lang

import io.jsonwebtoken.JwtFactory
import io.jsonwebtoken.TestJwtFactory
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.junit.Assert.assertNotNull

@RunWith(PowerMockRunner.class)
@PrepareForTest([Services])
class ServicesTest {

    @Test
    void testSuccessfulLoading() {
        def factory = Services.loadFirst(JwtFactory.class)

        assertNotNull factory

        org.junit.Assert.assertEquals(TestJwtFactory, factory.class)
    }

    @Test(expected = ImplementationNotFoundException)
    void testFailedLoading() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader()

        Thread.currentThread().setContextClassLoader(new NoServicesClassLoader(cl))

        Services.loadFirst(JwtFactory.class)
    }

    static class NoServicesClassLoader extends ClassLoader {
        private NoServicesClassLoader(ClassLoader parent) {
            super(parent)
        }

        @Override
        Enumeration<URL> getResources(String name) throws IOException {
            if (name.startsWith("META-INF/services/")) {
                return java.util.Collections.emptyEnumeration()
            } else {
                return super.getResources(name)
            }
        }
    }
}
