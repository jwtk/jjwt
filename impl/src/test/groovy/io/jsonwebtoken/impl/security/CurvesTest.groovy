package io.jsonwebtoken.impl.security

import org.junit.Test

import static org.junit.Assert.assertEquals

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
            } else {
                assertEquals it.getJcaName(), pair.getPublic().getAlgorithm()
                assertEquals it.getJcaName(), pair.getPrivate().getAlgorithm()
            }
        }
    }
}
