/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.impl.io

import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.io.JacksonSerializer
import io.jsonwebtoken.io.OrgJsonSerializer
import io.jsonwebtoken.gson.io.GsonSerializer
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
                if (JacksonSerializer.class.getName().equals(fqcn)) {
                    return false //skip it to allow the OrgJson impl to be created
                }
                return super.isAvailable(fqcn)
            }
        }

        def serializer = locator.getInstance()
        assertTrue serializer instanceof OrgJsonSerializer
    }
    
    @Test
    void testGson() {
        def locator = new RuntimeClasspathSerializerLocator() {
            @Override
            protected boolean isAvailable(String fqcn) {
                if (JacksonSerializer.class.getName().equals(fqcn)) {
                    return false //skip it to allow the Gson impl to be created
                }
                if (OrgJsonSerializer.class.getName().equals(fqcn)) {
                    return false //skip it to allow the Gson impl to be created
                }
                return super.isAvailable(fqcn)
            }
        }

        def serializer = locator.getInstance()
        assertTrue serializer instanceof GsonSerializer
    }
}
