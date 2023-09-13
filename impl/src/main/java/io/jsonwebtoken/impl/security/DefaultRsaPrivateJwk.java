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

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.Fields;
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

    static final Field<BigInteger> PRIVATE_EXPONENT = Fields.secretBigInt("d", "Private Exponent");
    static final Field<BigInteger> FIRST_PRIME = Fields.secretBigInt("p", "First Prime Factor");
    static final Field<BigInteger> SECOND_PRIME = Fields.secretBigInt("q", "Second Prime Factor");
    static final Field<BigInteger> FIRST_CRT_EXPONENT = Fields.secretBigInt("dp", "First Factor CRT Exponent");
    static final Field<BigInteger> SECOND_CRT_EXPONENT = Fields.secretBigInt("dq", "Second Factor CRT Exponent");
    static final Field<BigInteger> FIRST_CRT_COEFFICIENT = Fields.secretBigInt("qi", "First CRT Coefficient");
    static final Field<List<RSAOtherPrimeInfo>> OTHER_PRIMES_INFO =
            Fields.builder(RSAOtherPrimeInfo.class)
                    .setId("oth").setName("Other Primes Info")
                    .setConverter(RSAOtherPrimeInfoConverter.INSTANCE).list()
                    .build();

    static final Set<Field<?>> FIELDS = Collections.concat(DefaultRsaPublicJwk.FIELDS,
            PRIVATE_EXPONENT, FIRST_PRIME, SECOND_PRIME, FIRST_CRT_EXPONENT,
            SECOND_CRT_EXPONENT, FIRST_CRT_COEFFICIENT, OTHER_PRIMES_INFO
    );

    DefaultRsaPrivateJwk(JwkContext<RSAPrivateKey> ctx, RsaPublicJwk pubJwk) {
        super(ctx,
                // only public members are included in Private JWK Thumbprints per
                // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
                DefaultRsaPublicJwk.THUMBPRINT_FIELDS,
                pubJwk);
    }

    private static boolean equals(RSAOtherPrimeInfo a, RSAOtherPrimeInfo b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        return Fields.bytesEquals(a.getPrime(), b.getPrime()) &&
                Fields.bytesEquals(a.getExponent(), b.getExponent()) &&
                Fields.bytesEquals(a.getCrtCoefficient(), b.getCrtCoefficient());
    }

    private static boolean equalsOtherPrimes(FieldReadable a, FieldReadable b) {
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
                Fields.equals(this, jwk, PRIVATE_EXPONENT) &&
                Fields.equals(this, jwk, FIRST_PRIME) &&
                Fields.equals(this, jwk, SECOND_PRIME) &&
                Fields.equals(this, jwk, FIRST_CRT_EXPONENT) &&
                Fields.equals(this, jwk, SECOND_CRT_EXPONENT) &&
                Fields.equals(this, jwk, FIRST_CRT_COEFFICIENT) &&
                equalsOtherPrimes(this, (FieldReadable) jwk);
    }
}
