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
package io.jsonwebtoken.security

import io.jsonwebtoken.impl.security.ECCurve
import io.jsonwebtoken.impl.security.EdwardsCurve
import io.jsonwebtoken.impl.security.StandardCurves
import org.junit.Test

import static org.junit.Assert.assertSame
import static org.junit.Assert.assertTrue

class JwksCRVTest {

    @Test
    void testRegistry() {
        assertTrue Jwks.CRV.get() instanceof StandardCurves
    }

    @Test
    void testInstances() {
        assertSame ECCurve.P256, Jwks.CRV.P256
        assertSame ECCurve.P384, Jwks.CRV.P384
        assertSame ECCurve.P521, Jwks.CRV.P521
        assertSame EdwardsCurve.X25519, Jwks.CRV.X25519
        assertSame EdwardsCurve.X448, Jwks.CRV.X448
        assertSame EdwardsCurve.Ed25519, Jwks.CRV.Ed25519
        assertSame EdwardsCurve.Ed448, Jwks.CRV.Ed448
    }
}
