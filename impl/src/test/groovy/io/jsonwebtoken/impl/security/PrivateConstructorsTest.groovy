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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.Jwe
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.lang.Functions
import io.jsonwebtoken.lang.Classes
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.Suppliers
import org.junit.Test

import static org.junit.Assert.assertSame

class PrivateConstructorsTest {

    @Test
    void testPrivateCtors() { // for code coverage only
        new Classes()
        new KeysBridge()
        new JwksBridge()
        new Functions()
        new Jws.alg()
        new Jwe.alg()
        new Jwe.enc()
        new Jwts.SIG(); assertSame(Jws.alg.registry(), Jwts.SIG.get())
        new Jwts.ENC(); assertSame(Jwe.alg.registry(), Jwts.ENC.get())
        new Jwts.KEY(); assertSame(Jwe.enc.registry(), Jwts.KEY.get())
        new Jwts.ZIP()
        new Jwks.CRV()
        new Jwks.HASH()
        new Jwks.OP()
        new Suppliers()
    }
}
