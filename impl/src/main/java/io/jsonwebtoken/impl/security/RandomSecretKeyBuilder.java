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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class RandomSecretKeyBuilder extends DefaultSecretKeyBuilder {

    public RandomSecretKeyBuilder(String jcaName, int bitLength) {
        super(jcaName, bitLength);
    }

    @Override
    public SecretKey build() {
        byte[] bytes = new byte[this.BIT_LENGTH / Byte.SIZE];
        this.random.nextBytes(bytes);
        return new SecretKeySpec(bytes, this.JCA_NAME);
    }
}
