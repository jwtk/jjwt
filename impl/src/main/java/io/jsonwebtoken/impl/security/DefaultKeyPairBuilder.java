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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyPairBuilder;

import java.security.KeyPair;
import java.security.spec.AlgorithmParameterSpec;

public class DefaultKeyPairBuilder extends AbstractSecurityBuilder<KeyPair, KeyPairBuilder> implements KeyPairBuilder {

    private final String jcaName;
    private final int bitLength;
    private final AlgorithmParameterSpec params;

    public DefaultKeyPairBuilder(String jcaName) {
        this.jcaName = Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        this.bitLength = 0;
        this.params = null;
    }

    public DefaultKeyPairBuilder(String jcaName, int bitLength) {
        this.jcaName = Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        this.bitLength = Assert.gt(bitLength, 0, "bitLength must be a positive integer greater than 0");
        this.params = null;
    }

    public DefaultKeyPairBuilder(String jcaName, AlgorithmParameterSpec params) {
        this.jcaName = Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        this.params = Assert.notNull(params, "AlgorithmParameterSpec params cannot be null.");
        this.bitLength = 0;
    }

    @Override
    public KeyPair build() {
        JcaTemplate template = new JcaTemplate(this.jcaName, this.provider, this.random);
        if (this.params != null) {
            return template.generateKeyPair(this.params);
        } else if (this.bitLength > 0) {
            return template.generateKeyPair(this.bitLength);
        } else {
            return template.generateKeyPair();
        }
    }
}
