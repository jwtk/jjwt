/*
 * Copyright (C) 2015 jsonwebtoken.io
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

import android.util.Base64
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.*
import static org.junit.Assert.*
import static org.powermock.api.easymock.PowerMock.mockStatic
import static org.powermock.api.easymock.PowerMock.replayAll
import static org.powermock.api.easymock.PowerMock.verifyAll

@RunWith(PowerMockRunner.class)
@PrepareForTest([Base64.class])
class AndroidBase64CodecTest {

    @Test
    public void testEncode() {

        mockStatic(Base64.class);

        byte[] bytes = new byte[32];
        String s = "foo";
        int flags = Base64.NO_PADDING | Base64.NO_WRAP;

        expect(Base64.encodeToString(same(bytes), eq(flags))).andReturn(s);
        replayAll();

        AndroidBase64Codec codec = new AndroidBase64Codec();

        String val = codec.encode(bytes);

        verifyAll();
        assertEquals(val, s);
    }

    @Test
    public void testDecode() {

        mockStatic(Base64.class);

        byte[] bytes = new byte[32];
        String s = "foo";

        expect(Base64.decode((String)same(s), eq(Base64.DEFAULT))).andReturn(bytes);
        replayAll();

        AndroidBase64Codec codec = new AndroidBase64Codec();

        def val = codec.decode(s);

        verifyAll();
        assertSame bytes, val
    }
}
