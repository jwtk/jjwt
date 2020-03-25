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
package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.Keys
import org.junit.Test

import static org.junit.Assert.assertNotNull
import static org.junit.Assert.assertSame

class DefaultJwtSignerTest {

    @Test
    //TODO: remove this before 1.0 since it tests a deprecated method
    @Deprecated
    //remove just before 1.0.0 release
    void testDeprecatedTwoArgCtor() {

        def alg = SignatureAlgorithm.HS256
        def key = Keys.secretKeyFor(alg)
        def signer = new DefaultJwtSigner(alg, key)

        assertNotNull signer.signer
        assertSame Encoders.BASE64URL, signer.base64UrlEncoder
    }

    @Test
    //TODO: remove this before 1.0 since it tests a deprecated method
    @Deprecated
    //remove just before 1.0.0 release
    void testDeprecatedThreeArgCtor() {

        def alg = SignatureAlgorithm.HS256
        def key = Keys.secretKeyFor(alg)
        def signer = new DefaultJwtSigner(DefaultSignerFactory.INSTANCE, alg, key)

        assertNotNull signer.signer
        assertSame Encoders.BASE64URL, signer.base64UrlEncoder
    }
}
