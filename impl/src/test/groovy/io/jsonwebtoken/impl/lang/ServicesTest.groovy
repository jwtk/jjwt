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
import org.junit.After
import org.junit.Test

import static org.junit.Assert.*

class ServicesTest {

    @Test
    void testSuccessfulLoading() {
        def factory = Services.loadFirst(StubService)
        assertNotNull factory
        assertEquals(DefaultStubService, factory.class)
    }

    @Test(expected = UnavailableImplementationException)
    void testLoadFirstUnavailable() {
        Services.loadFirst(NoService.class)
    }

    @Test
    void testLoadAllAvailable() {
        def list = Services.loadAll(StubService.class)
        assertEquals 1, list.size()
        assertTrue list[0] instanceof StubService
    }

    @Test(expected = UnavailableImplementationException)
    void testLoadAllUnavailable() {
        Services.loadAll(NoService.class)
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

    @After
    void resetCache() {
        Services.reload();
    }

    interface NoService {} // no implementations
}
