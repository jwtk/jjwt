/*
 * Copyright © 2023 jsonwebtoken.io
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
import io.jsonwebtoken.security.KeySupplier;

import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class PrivateECKey implements PrivateKey, ECKey, KeySupplier<PrivateKey> {

    private final PrivateKey privateKey;
    private final ECParameterSpec params;

    public PrivateECKey(PrivateKey privateKey, ECParameterSpec params) {
        this.privateKey = Assert.notNull(privateKey, "PrivateKey cannot be null.");
        this.params = Assert.notNull(params, "ECParameterSpec cannot be null.");
    }

    @Override
    public String getAlgorithm() {
        return this.privateKey.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return this.privateKey.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return this.privateKey.getEncoded();
    }

    @Override
    public ECParameterSpec getParams() {
        return this.params;
    }

    @Override
    public PrivateKey getKey() {
        return this.privateKey;
    }
}
