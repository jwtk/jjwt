/*
 * Copyright (C) 2016 jsonwebtoken.io
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
package io.jsonwebtoken.impl.crypto

import org.junit.Test
import static org.junit.Assert.*

class DefaultAuthenticatedEncryptionResultTest {

    private byte[] generateData() {
        byte[] data = new byte[32];
        new Random().nextBytes(data) //does not need to be secure for this test
        return data;
    }

    @Test
    void testCompactWithoutIv() {

        byte[] ciphertext = generateData()
        byte[] tag = generateData()

        byte[] combined = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);

        def res = new DefaultAuthenticatedEncryptionResult(null, ciphertext, tag)
        byte[] compact = res.compact()

        assertTrue(Arrays.equals(combined, compact))
    }

    @Test
    void testCompactWithIv() {

        byte[] iv = generateData()
        byte[] ciphertext = generateData()
        byte[] tag = generateData()

        byte[] combined = new byte[iv.length + ciphertext.length + tag.length];
        System.arraycopy(iv, 0, combined, 0, iv.length)
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        System.arraycopy(tag, 0, combined, iv.length + ciphertext.length, tag.length);

        def res = new DefaultAuthenticatedEncryptionResult(iv, ciphertext, tag)
        byte[] compact = res.compact()

        assertTrue(Arrays.equals(combined, compact))
    }
}
