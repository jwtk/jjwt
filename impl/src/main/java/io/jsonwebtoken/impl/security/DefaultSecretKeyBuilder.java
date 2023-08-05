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
import io.jsonwebtoken.security.SecretKeyBuilder;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultSecretKeyBuilder implements SecretKeyBuilder {

    protected final String JCA_NAME;
    protected final int BIT_LENGTH;
    protected Provider provider;
    protected SecureRandom random;

    public DefaultSecretKeyBuilder(String jcaName, int bitLength) {
        this.JCA_NAME = Assert.hasText(jcaName, "jcaName cannot be null or empty.");
        if (bitLength % Byte.SIZE != 0) {
            String msg = "bitLength must be an even multiple of 8";
            throw new IllegalArgumentException(msg);
        }
        this.BIT_LENGTH = Assert.gt(bitLength, 0, "bitLength must be > 0");
        random(Randoms.secureRandom());
    }

    @Override
    public SecretKeyBuilder provider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public SecretKeyBuilder random(SecureRandom random) {
        this.random = random != null ? random : Randoms.secureRandom();
        return this;
    }

    @Override
    public SecretKey build() {
        JcaTemplate template = new JcaTemplate(JCA_NAME, this.provider, this.random);
        return template.generateSecretKey(this.BIT_LENGTH);
    }
}
