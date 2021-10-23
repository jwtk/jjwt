package io.jsonwebtoken.impl.security

import io.jsonwebtoken.JweHeader
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.security.*
import org.junit.Ignore
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

@SuppressWarnings('SpellCheckingInspection')
class Pbes2HsAkwAlgorithmTest {

    private static PasswordKey KEY = Keys.forPassword("12345678".toCharArray())
    private static List<Pbes2HsAkwAlgorithm> ALGS = [KeyAlgorithms.PBES2_HS256_A128KW,
                                                     KeyAlgorithms.PBES2_HS384_A192KW,
                                                     KeyAlgorithms.PBES2_HS512_A256KW] as List<Pbes2HsAkwAlgorithm>

    @Test
    void testInsufficientIterations() {
        for (Pbes2HsAkwAlgorithm alg : ALGS) {
            int iterations = 50 // must be 1000 or more
            JweHeader header = Jwts.jweHeader().setPbes2Count(iterations)
            KeyRequest<PasswordKey> req = new DefaultKeyRequest<>(null, null, KEY, header, EncryptionAlgorithms.A256GCM)
            try {
                alg.getEncryptionKey(req)
                fail()
            } catch (IllegalArgumentException iae) {
                assertEquals Pbes2HsAkwAlgorithm.MIN_ITERATIONS_MSG_PREFIX + iterations, iae.getMessage()

            }
        }
    }

    @Ignore
    // for manual/developer testing only.  Takes a long time and there is no deterministic output to assert
    @Test
    void test() {

        def alg = KeyAlgorithms.PBES2_HS256_A128KW

        int desiredMillis = 100
        int iterations = KeyAlgorithms.estimateIterations(alg, desiredMillis)
        println "Estimated iterations: $iterations"

        int tries = 30
        int skip = 6
        //double scale = 0.5035246727

        def password = 'hellowor'.toCharArray()
        def header = new DefaultJweHeader().setPbes2Count(iterations)
        def key = Keys.forPassword(password)
        def req = new DefaultKeyRequest(null, null, key, header, EncryptionAlgorithms.A128GCM)
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
}
