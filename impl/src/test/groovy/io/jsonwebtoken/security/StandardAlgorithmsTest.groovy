package io.jsonwebtoken.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.lang.Registry
import org.junit.Test

import static org.junit.Assert.*

class StandardAlgorithmsTest {

    static def registries = [Jwts.SIG, Jwts.ENC, Jwts.KEY, Jwks.HASH] as List<Registry<String, ?>>

    @Test
    void testSize() {
        assertEquals 14, Jwts.SIG.size()
        assertEquals 6, Jwts.ENC.size()
        assertEquals 17, Jwts.KEY.size()
        assertEquals 6, Jwks.HASH.size()
    }

    private static void eachRegAlg(Closure c) {
        registries.each { reg -> reg.values().each { c(reg, it) } }
    }

    @Test
    void testGet() {
        eachRegAlg { reg, alg ->
            assertSame alg, reg.get(alg.getId())
        }
    }

    @Test
    void testGetCaseInsensitive() {
        eachRegAlg { reg, alg ->
            assertSame alg, reg.get(alg.getId().toLowerCase())
        }
    }

    @Test
    void testGetWithInvalidId() {
        //unlike the 'find' paradigm, 'get' requires the value to exist
        registries.each {reg ->
            //noinspection GroovyUnusedCatchParameter
            try {
                reg.get('invalid')
                fail()
            } catch (IllegalArgumentException expected) {
            }
        }
    }

    @Test
    void testFindById() {
        eachRegAlg { reg, alg ->
            assertSame alg, reg.find(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        eachRegAlg { reg, alg ->
            assertSame alg, reg.find(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        registries.each {reg ->
            assertNull reg.find('invalid')
        }
    }

}
