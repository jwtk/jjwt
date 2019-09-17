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

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.JacksonDeserializer
import io.jsonwebtoken.io.OrgJsonDeserializer
import io.jsonwebtoken.gson.io.GsonDeserializer
import org.junit.After
import org.junit.Before
import org.junit.Test

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class RuntimeClasspathDeserializerLocatorTest {

    @Before
    void setUp() {
        RuntimeClasspathDeserializerLocator.DESERIALIZER.set(null)
    }

    @After
    void teardown() {
        RuntimeClasspathDeserializerLocator.DESERIALIZER.set(null)
    }

    @Test
    void testClassIsNotAvailable() {
        def locator = new RuntimeClasspathDeserializerLocator() {
            @Override
            protected boolean isAvailable(String fqcn) {
                return false
            }
        }
        try {
            locator.getInstance()
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
        def locator = new RuntimeClasspathDeserializerLocator() {
            @Override
            protected boolean isAvailable(String fqcn) {
                if (JacksonDeserializer.class.getName().equals(fqcn)) {
                    return false; //skip it to allow the OrgJson impl to be created
                }
                return super.isAvailable(fqcn)
            }
        }

        def deserializer = locator.getInstance()
        assertTrue deserializer instanceof OrgJsonDeserializer
    }
    
    @Test
    void testGson() {
        def locator = new RuntimeClasspathDeserializerLocator() {
            @Override
            protected boolean isAvailable(String fqcn) {
                if (JacksonDeserializer.class.getName().equals(fqcn)) {
                    return false; //skip it to allow the Gson impl to be created
                }
                if (OrgJsonDeserializer.class.getName().equals(fqcn)) {
                    return false; //skip it to allow the Gson impl to be created
                }
                return super.isAvailable(fqcn)
            }
        }

        def deserializer = locator.getInstance()
        assertTrue deserializer instanceof GsonDeserializer
    }
}
