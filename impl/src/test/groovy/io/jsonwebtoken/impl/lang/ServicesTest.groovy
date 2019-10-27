/*
 * Copyright (C) 2019 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.impl.DefaultStubService
import io.jsonwebtoken.StubService
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull

@RunWith(PowerMockRunner.class)
@PrepareForTest([Services])
class ServicesTest {

    @Test
    void testSuccessfulLoading() {
        def factory = Services.loadFirst(StubService)
        assertNotNull factory
        assertEquals(DefaultStubService, factory.class)
    }

    @Test(expected = UnavailableImplementationException)
    void testLoadFirstUnavailable() {
        NoServicesClassLoader.runWith {
            Services.loadFirst(StubService.class)
        }
    }

    @Test(expected = UnavailableImplementationException)
    void testLoadAllUnavailable() {
        NoServicesClassLoader.runWith {
            Services.loadAll(StubService.class)
        }
    }

    @Test
    void testPrivateConstructor() {
        new Services(); // not allowed in Java, including here for test coverage
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

        static void runWith(Closure closure) {
            ClassLoader originalClassloader = Thread.currentThread().getContextClassLoader()
            try {
                Thread.currentThread().setContextClassLoader(new NoServicesClassLoader(originalClassloader))
                closure.run()
            } finally {
                if (originalClassloader != null) {
                    Thread.currentThread().setContextClassLoader(originalClassloader)
                }
            }
        }
    }
}
