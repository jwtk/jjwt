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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.RsaPrivateJwk;
import io.jsonwebtoken.security.RsaPublicJwk;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAOtherPrimeInfo;
import java.util.List;
import java.util.Set;

import static io.jsonwebtoken.impl.security.DefaultRsaPublicJwk.equalsPublic;

class DefaultRsaPrivateJwk extends AbstractPrivateJwk<RSAPrivateKey, RSAPublicKey, RsaPublicJwk> implements RsaPrivateJwk {

    static final Parameter<BigInteger> PRIVATE_EXPONENT = Parameters.secretBigInt("d", "Private Exponent");
    static final Parameter<BigInteger> FIRST_PRIME = Parameters.secretBigInt("p", "First Prime Factor");
    static final Parameter<BigInteger> SECOND_PRIME = Parameters.secretBigInt("q", "Second Prime Factor");
    static final Parameter<BigInteger> FIRST_CRT_EXPONENT = Parameters.secretBigInt("dp", "First Factor CRT Exponent");
    static final Parameter<BigInteger> SECOND_CRT_EXPONENT = Parameters.secretBigInt("dq", "Second Factor CRT Exponent");
    static final Parameter<BigInteger> FIRST_CRT_COEFFICIENT = Parameters.secretBigInt("qi", "First CRT Coefficient");
    static final Parameter<List<RSAOtherPrimeInfo>> OTHER_PRIMES_INFO =
            Parameters.builder(RSAOtherPrimeInfo.class)
                    .setId("oth").setName("Other Primes Info")
                    .setConverter(RSAOtherPrimeInfoConverter.INSTANCE).list()
                    .build();

    static final Set<Parameter<?>> PARAMS = Collections.concat(DefaultRsaPublicJwk.PARAMS,
            PRIVATE_EXPONENT, FIRST_PRIME, SECOND_PRIME, FIRST_CRT_EXPONENT,
            SECOND_CRT_EXPONENT, FIRST_CRT_COEFFICIENT, OTHER_PRIMES_INFO
    );

    DefaultRsaPrivateJwk(JwkContext<RSAPrivateKey> ctx, RsaPublicJwk pubJwk) {
        super(ctx,
                // only public members are included in Private JWK Thumbprints per
                // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
                DefaultRsaPublicJwk.THUMBPRINT_PARAMS,
                pubJwk);
    }

    private static boolean equals(RSAOtherPrimeInfo a, RSAOtherPrimeInfo b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        return Parameters.bytesEquals(a.getPrime(), b.getPrime()) &&
                Parameters.bytesEquals(a.getExponent(), b.getExponent()) &&
                Parameters.bytesEquals(a.getCrtCoefficient(), b.getCrtCoefficient());
    }

    private static boolean equalsOtherPrimes(ParameterReadable a, ParameterReadable b) {
        List<RSAOtherPrimeInfo> aOthers = a.get(OTHER_PRIMES_INFO);
        List<RSAOtherPrimeInfo> bOthers = b.get(OTHER_PRIMES_INFO);
        int aSize = Collections.size(aOthers);
        int bSize = Collections.size(bOthers);
        if (aSize != bSize) return false;
        if (aSize == 0) return true;
        RSAOtherPrimeInfo[] aInfos = aOthers.toArray(new RSAOtherPrimeInfo[0]);
        RSAOtherPrimeInfo[] bInfos = bOthers.toArray(new RSAOtherPrimeInfo[0]);
        for (int i = 0; i < aSize; i++) {
            if (!equals(aInfos[i], bInfos[i])) return false;
        }
        return true;
    }

    @Override
    protected boolean equals(PrivateJwk<?, ?, ?> jwk) {
        return jwk instanceof RsaPrivateJwk && equalsPublic(this, jwk) &&
                Parameters.equals(this, jwk, PRIVATE_EXPONENT) &&
                Parameters.equals(this, jwk, FIRST_PRIME) &&
                Parameters.equals(this, jwk, SECOND_PRIME) &&
                Parameters.equals(this, jwk, FIRST_CRT_EXPONENT) &&
                Parameters.equals(this, jwk, SECOND_CRT_EXPONENT) &&
                Parameters.equals(this, jwk, FIRST_CRT_COEFFICIENT) &&
                equalsOtherPrimes(this, (ParameterReadable) jwk);
    }
}
