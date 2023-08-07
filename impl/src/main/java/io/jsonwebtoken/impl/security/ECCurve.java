/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.security.KeyPairBuilder;

import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

public class ECCurve extends DefaultCurve {

    static final String KEY_PAIR_GENERATOR_JCA_NAME = "EC";

    private final ECParameterSpec spec;

    public ECCurve(String id, String jcaName) {
        super(id, jcaName);
        JcaTemplate template = new JcaTemplate(KEY_PAIR_GENERATOR_JCA_NAME, null);
        this.spec = template.withAlgorithmParameters(new CheckedFunction<AlgorithmParameters, ECParameterSpec>() {
            @Override
            public ECParameterSpec apply(AlgorithmParameters params) throws Exception {
                params.init(new ECGenParameterSpec(getJcaName()));
                return params.getParameterSpec(ECParameterSpec.class);
            }
        });
    }

    public ECParameterSpec toParameterSpec() {
        return this.spec;
    }

    /**
     * Returns {@code true} if this elliptic curve contains the specified {@code point}, {@code false}
     * otherwise.  Assumes elliptic curves over finite fields adhering to the reduced (a.k.a short or narrow)
     * Weierstrass form:
     * <p>
     * <code>y<sup>2</sup> = x<sup>3</sup> + ax + b</code>
     * </p>
     *
     * @param point a point that may or may not be defined on this elliptic curve
     * @return {@code true} if this elliptic curve contains the specified {@code point}, {@code false} otherwise.
     */
    public boolean contains(ECPoint point) {
        return AbstractEcJwkFactory.contains(spec.getCurve(), point);
    }

    @Override
    public KeyPairBuilder keyPair() {
        return new DefaultKeyPairBuilder(KEY_PAIR_GENERATOR_JCA_NAME, toParameterSpec());
    }
}
