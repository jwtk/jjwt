package io.jsonwebtoken.impl.security

import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

class CurvesTest {

    @Test
    void testCtor() {
        new Curves() // test coverage only
    }

    @Test
    void testFindById() {
        Curves.VALUES.each {
            it.equals(Curves.findById(it.getId()))
        }
    }

    @Test
    void testFindByJcaName() {
        Curves.VALUES.each {
            it.equals(Curves.findByJcaName(it.getJcaName()))
        }
    }

    @Test
    void testFindByEllipticCurve() {
        Curves.EC_CURVES.each {
            it.equals(Curves.findBy(it.toParameterSpec().getCurve()))
        }
    }

    @Test
    void testKeyPairBuilders() {
        Curves.VALUES.each {
            def pair = it.keyPairBuilder().build()
            if (it instanceof ECCurve) {
                assertEquals ECCurve.KEY_PAIR_GENERATOR_JCA_NAME, pair.getPublic().getAlgorithm()
                assertEquals ECCurve.KEY_PAIR_GENERATOR_JCA_NAME, pair.getPrivate().getAlgorithm()
            } else { // edwards curve
                String jcaName = it.getJcaName()
                String pubAlg = pair.getPublic().getAlgorithm()
                String privAlg = pair.getPrivate().getAlgorithm()

                if (jcaName.startsWith('X')) { // X*** curves
                    //BC will retain exact alg, OpenJDK >= 11 will use 'XDH' instead, both are valid:
                    assertTrue(pubAlg.equals(jcaName) || pubAlg.equals('XDH'))
                    assertTrue(privAlg.equals(jcaName) || privAlg.equals('XDH'))
                } else { // Ed*** curves
                    //BC will retain exact alg, OpenJDK >= 15 will use 'EdDSA' instead, both are valid:
                    assertTrue(pubAlg.equals(jcaName) || pubAlg.equals('EdDSA'))
                    assertTrue(privAlg.equals(jcaName) || privAlg.equals('EdDSA'))
                }
            }
        }
    }
}
