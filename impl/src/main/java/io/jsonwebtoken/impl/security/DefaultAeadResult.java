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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadResult;

public class DefaultAeadResult implements AeadResult {

    private final byte[] TAG;
    private final byte[] IV;

    public DefaultAeadResult(byte[] tag, byte[] iv) {
        this.IV = Assert.notEmpty(iv, "initialization vector cannot be null or empty.");
        this.TAG = Assert.notEmpty(tag, "authentication tag cannot be null or empty.");
    }

    @Override
    public byte[] getDigest() {
        return this.TAG;
    }

    @Override
    public byte[] getInitializationVector() {
        return this.IV;
    }
}
