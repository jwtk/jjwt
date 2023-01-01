/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import java.security.interfaces.RSAMultiPrimePrivateCrtKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.RSAOtherPrimeInfo

class TestRSAMultiPrimePrivateCrtKey extends TestRSAPrivateKey implements RSAMultiPrimePrivateCrtKey {

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
