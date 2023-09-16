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
package io.jsonwebtoken.issues

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.security.TestKeys
import org.junit.Test

/**
 * https://github.com/jwtk/jjwt/issues/438
 */
class Issue438Test {

    @Test(expected = UnsupportedJwtException /* not IllegalArgumentException */)
    void testIssue438() {
        String jws = Jwts.builder().issuer('test').signWith(TestKeys.RS256.pair.private).compact()
        Jwts.parser().verifyWith(TestKeys.HS256).build().parseClaimsJws(jws)
    }
}
