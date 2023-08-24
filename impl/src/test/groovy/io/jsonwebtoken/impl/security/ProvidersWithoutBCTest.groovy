/*
 * Copyright (C) 2022 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.lang.Classes
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.eq
import static org.easymock.EasyMock.expect
import static org.junit.Assert.assertFalse
import static org.junit.Assert.assertNull
import static org.powermock.api.easymock.PowerMock.*

@RunWith(PowerMockRunner.class)
@PrepareForTest([Classes])
class ProvidersWithoutBCTest {

    @After
    void after() {
        ProvidersTest.cleanup() //ensure environment is clean
    }

    @Test
    void testBouncyCastleClassNotAvailable() {
        mockStatic(Classes)
        expect(Classes.isAvailable(eq("org.bouncycastle.jce.provider.BouncyCastleProvider"))).andReturn(Boolean.FALSE).anyTimes()
        replay Classes
        assertNull Providers.findBouncyCastle() // one should not be created/exist
        verify Classes
        assertFalse ProvidersTest.bcRegistered() // nothing should be in the environment
    }
}
