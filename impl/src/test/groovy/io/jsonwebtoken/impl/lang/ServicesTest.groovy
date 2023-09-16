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

import io.jsonwebtoken.StubService
import io.jsonwebtoken.impl.DefaultStubService
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.api.easymock.PowerMock
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import java.lang.reflect.Field

import static org.junit.Assert.*

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

    @Test
    void testLoadAllAvailable() {
        def list = Services.loadAll(StubService.class)
        assertEquals 1, list.size()
        assertTrue list[0] instanceof StubService
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

    @Test
    void testClassLoaderAccessorList() {
        List<Services.ClassLoaderAccessor> accessorList = Services.CLASS_LOADER_ACCESSORS
        assertEquals("Expected 3 ClassLoaderAccessor to be found", 3, accessorList.size())
        assertEquals(Thread.currentThread().getContextClassLoader(), accessorList.get(0).getClassLoader())
        assertEquals(Services.class.getClassLoader(), accessorList.get(1).getClassLoader())
        assertEquals(ClassLoader.getSystemClassLoader(), accessorList.get(2).getClassLoader())
    }

    static class NoServicesClassLoader extends ClassLoader {
        private NoServicesClassLoader(ClassLoader parent) {
            super(parent)
        }

        @Override
        Enumeration<URL> getResources(String name) throws IOException {
            if (name.startsWith("META-INF/services/")) {
                return Collections.emptyEnumeration()
            } else {
                return super.getResources(name)
            }
        }

        static void runWith(Closure closure) {
            Field field = PowerMock.field(Services.class, "CLASS_LOADER_ACCESSORS")
            def originalValue = field.get(Services.class)
            try {
                // use powermock to change the list of the classloaders we are using
                List<Services.ClassLoaderAccessor> classLoaderAccessors = [
                        new Services.ClassLoaderAccessor() {
                            @Override
                            ClassLoader getClassLoader() {
                                return new NoServicesClassLoader(Thread.currentThread().getContextClassLoader())
                            }
                        }
                ]
                field.set(Services.class, classLoaderAccessors)
                closure.run()
            } finally {
                field.set(Services.class, originalValue)
            }
        }
    }
}
