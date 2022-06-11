/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl


import org.junit.Before
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

class DefaultJweHeaderBuilderTest {

    DefaultJweHeaderBuilder builder

    @Before
    void testSetUp() {
        builder = new DefaultJweHeaderBuilder()
    }

    @Test
    void testNewHeader() {
        assertTrue builder.header instanceof DefaultJweHeader
    }

    @Test
    void testSetAgreementPartyUInfo() {
        def info = "UInfo".getBytes(StandardCharsets.UTF_8)
        assertArrayEquals info, builder.setAgreementPartyUInfo(info).build().getAgreementPartyUInfo()
    }

    @Test
    void testSetAgreementPartyUInfoString() {
        def s = "UInfo"
        def info = s.getBytes(StandardCharsets.UTF_8)
        assertArrayEquals info, builder.setAgreementPartyUInfo(s).build().getAgreementPartyUInfo()
    }

    @Test
    void testSetAgreementPartyVInfo() {
        def info = "VInfo".getBytes(StandardCharsets.UTF_8)
        assertArrayEquals info, builder.setAgreementPartyVInfo(info).build().getAgreementPartyVInfo()
    }

    @Test
    void testSetAgreementPartyVInfoString() {
        def s = "VInfo"
        def info = s.getBytes(StandardCharsets.UTF_8)
        assertArrayEquals info, builder.setAgreementPartyVInfo(s).build().getAgreementPartyVInfo()
    }

    @Test
    void testSetPbes2Count() {
        int count = 4096
        assertEquals count, builder.setPbes2Count(count).build().getPbes2Count()
    }
}
