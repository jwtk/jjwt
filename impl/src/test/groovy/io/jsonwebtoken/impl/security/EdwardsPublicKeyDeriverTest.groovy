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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class EdwardsPublicKeyDeriverTest {

    @Test
    void testDeriveWithNonEdwardsKey() {
        def rsaPrivKey = Jwts.SIG.RS256.keyPairBuilder().build().getPrivate()
        try {
            EdwardsPublicKeyDeriver.INSTANCE.apply(rsaPrivKey)
            fail()
        } catch (UnsupportedKeyException uke) {
            String expectedMsg = "Unable to derive Edwards-curve PublicKey for specified PrivateKey: ${KeysBridge.toString(rsaPrivKey)}"
            assertEquals(expectedMsg, uke.getMessage())
        }
    }
}
