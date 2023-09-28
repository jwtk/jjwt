/*
 * Copyright © 2023 jsonwebtoken.io
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

import io.jsonwebtoken.ClaimsMutator
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.assertSame

class DelegateAudienceCollectionTest {

    @Test
    void clear() {
        ClaimsMutator.AudienceCollection delegate = createMock(ClaimsMutator.AudienceCollection)
        expect(delegate.clear()).andReturn(delegate)
        replay(delegate)
        def c = new DelegateAudienceCollection(this, delegate)
        assertSame c, c.clear()
        verify delegate
    }

    @Test
    void remove() {
        String val = 'hello'
        ClaimsMutator.AudienceCollection delegate = createMock(ClaimsMutator.AudienceCollection)
        expect(delegate.remove(same(val))).andReturn(delegate)
        replay(delegate)
        def c = new DelegateAudienceCollection(this, delegate)
        assertSame c, c.remove(val)
        verify delegate
    }
}
