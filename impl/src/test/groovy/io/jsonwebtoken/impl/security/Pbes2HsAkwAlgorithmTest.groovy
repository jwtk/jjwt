package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.security.EncryptionAlgorithms
import io.jsonwebtoken.security.KeyAlgorithms
import io.jsonwebtoken.security.Keys
import org.junit.Ignore
import org.junit.Test

class Pbes2HsAkwAlgorithmTest {

    @Ignore // for manual/developer testing only.  Takes a long time and there is no deterministic output to assert
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
        def key = Keys.forPbe().setPassword(password).setIterations(iterations).build()
        def req = new DefaultKeyRequest(null, null, key, new DefaultJweHeader(), EncryptionAlgorithms.A128GCM)
        int sum = 0;
        for(int i = 0; i < tries; i++) {
            long start = System.currentTimeMillis()
            alg.getEncryptionKey(req)
            long end = System.currentTimeMillis()
            long duration = end - start;
            if (i >= skip) {
                sum+= duration
            }
            println "Try $i: ${alg.id} took $duration millis"
        }
        long avg = Math.round(sum / (tries - skip))
        println "Average duration: $avg"
        println "scale factor: ${desiredMillis / avg}"
    }
}
