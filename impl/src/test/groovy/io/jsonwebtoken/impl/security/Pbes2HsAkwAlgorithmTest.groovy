/*
 * Copyright (C) 2020 jsonwebtoken.io
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
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.DefaultJweHeaderMutator
import io.jsonwebtoken.impl.DefaultMutableJweHeader
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.KeyRequest
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.Password
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

@SuppressWarnings('SpellCheckingInspection')
class Pbes2HsAkwAlgorithmTest {

    private static Password KEY = Keys.password("12345678".toCharArray())
    private static List<Pbes2HsAkwAlgorithm> ALGS = [Jwts.KEY.PBES2_HS256_A128KW,
                                                     Jwts.KEY.PBES2_HS384_A192KW,
                                                     Jwts.KEY.PBES2_HS512_A256KW] as List<Pbes2HsAkwAlgorithm>

    @Test
    void testInsufficientIterations() {
        for (Pbes2HsAkwAlgorithm alg : ALGS) {
            int iterations = 50 // must be 1000 or more
            def header = Jwts.header().pbes2Count(iterations) as DefaultJweHeaderMutator
            def mutable = new DefaultMutableJweHeader(header)
            KeyRequest<Password> req = new DefaultKeyRequest<>(KEY, null, null, mutable, Jwts.ENC.A256GCM)
            try {
                alg.getEncryptionKey(req)
                fail()
            } catch (IllegalArgumentException iae) {
                assertEquals Pbes2HsAkwAlgorithm.MIN_ITERATIONS_MSG_PREFIX + iterations, iae.getMessage()
            }
        }
    }

    /**
     * @since 0.12.4
     */
    @Test
    void testExceedsMaxIterations() {
        for (Pbes2HsAkwAlgorithm alg : ALGS) {
            def password = Keys.password('correct horse battery staple'.toCharArray())
            def iterations = alg.MAX_ITERATIONS + 1
            // we make the JWE string directly from JSON here (instead of using Jwts.builder()) to avoid
            // the computational time it would take to create such JWEs with excessive iterations as well as
            // avoid the builder throwing any exceptions (and this is what a potential attacker would do anyway):
            def headerJson = """
            {
              "p2c": ${iterations},
              "p2s": "831BG_z_ZxkN7Rnt5v1iYm1A0bn6VEuxpW4gV7YBMoE",
              "alg": "${alg.id}",
              "enc": "A256GCM"
            }"""
            def jwe = Encoders.BASE64URL.encode(Strings.utf8(headerJson)) +
                    '.OSAhMk3FtaCeZ5v1c8bWBgssEVqx2mCPUEnJUsg4hwIQyrUP-LCYkg.' +
                    'K4R_-zb4qaZ3R0W8.sGS4mcT_xBhZC1d7G-g.kWqd_4sEsaKrWE_hMZ5HmQ'
            try {
                Jwts.parser().decryptWith(password).build().parse(jwe)
            } catch (UnsupportedJwtException expected) {
                String msg = "JWE Header 'p2c' (PBES2 Count) value ${iterations} exceeds ${alg.id} maximum allowed " +
                        "value ${alg.MAX_ITERATIONS}. The larger value is rejected to help mitigate potential " +
                        "Denial of Service attacks."
                //println msg
                assertEquals msg, expected.message
            }
        }
    }

    // for manual/developer testing only.  Takes a long time and there is no deterministic output to assert
    /*
    @Test
    void test() {

        def alg = Jwts.KEY.PBES2_HS256_A128KW

        int desiredMillis = 100
        int iterations = Jwts.KEY.estimateIterations(alg, desiredMillis)
        println "Estimated iterations: $iterations"

        int tries = 30
        int skip = 6
        //double scale = 0.5035246727

        def password = 'hellowor'.toCharArray()
        def header = new DefaultJweHeader().pbes2Count(iterations)
        def key = Keys.password(password)
        def req = new DefaultKeyRequest(null, null, key, header, Jwts.ENC.A128GCM)
        int sum = 0
        for (int i = 0; i < tries; i++) {
            long start = System.currentTimeMillis()
            alg.getEncryptionKey(req)
            long end = System.currentTimeMillis()
            long duration = end - start
            if (i >= skip) {
                sum += duration
            }
            println "Try $i: ${alg.id} took $duration millis"
        }
        long avg = Math.round(sum / (tries - skip))
        println "Average duration: $avg"
        println "scale factor: ${desiredMillis / avg}"
    }
     */
}
