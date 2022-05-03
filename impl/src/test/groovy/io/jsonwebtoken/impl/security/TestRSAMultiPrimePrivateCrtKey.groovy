package io.jsonwebtoken.impl.security

import java.security.interfaces.RSAMultiPrimePrivateCrtKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.RSAOtherPrimeInfo

class TestRSAMultiPrimePrivateCrtKey extends TestRSAPrivateKey<RSAPrivateCrtKey> implements RSAMultiPrimePrivateCrtKey {

    private final List<RSAOtherPrimeInfo> infos

    TestRSAMultiPrimePrivateCrtKey(RSAPrivateCrtKey src, List<RSAOtherPrimeInfo> infos) {
        super(src)
        this.infos = infos
    }

    @Override
    BigInteger getPublicExponent() {
        return src.publicExponent
    }

    @Override
    BigInteger getPrimeP() {
        return src.primeP
    }

    @Override
    BigInteger getPrimeQ() {
        return src.primeQ
    }

    @Override
    BigInteger getPrimeExponentP() {
        return src.primeExponentP
    }

    @Override
    BigInteger getPrimeExponentQ() {
        return src.primeExponentQ
    }

    @Override
    BigInteger getCrtCoefficient() {
        return src.crtCoefficient
    }

    @Override
    RSAOtherPrimeInfo[] getOtherPrimeInfo() {
        return infos as RSAOtherPrimeInfo[]
    }
}
