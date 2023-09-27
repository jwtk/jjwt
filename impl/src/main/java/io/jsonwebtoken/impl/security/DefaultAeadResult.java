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
import io.jsonwebtoken.security.DigestSupplier;
import io.jsonwebtoken.security.IvSupplier;

import java.io.OutputStream;

public class DefaultAeadResult implements AeadResult, DigestSupplier, IvSupplier {

    private final OutputStream out;
    private byte[] tag;
    private byte[] iv;

    public DefaultAeadResult(OutputStream out) {
        this.out = Assert.notNull(out, "OutputStream cannot be null.");
    }

    @Override
    public OutputStream getOutputStream() {
        return this.out;
    }

    @Override
    public byte[] getDigest() {
        return this.tag;
    }

    @Override
    public AeadResult setTag(byte[] tag) {
        this.tag = Assert.notEmpty(tag, "Authentication Tag cannot be null or empty.");
        return this;
    }

    @Override
    public AeadResult setIv(byte[] iv) {
        this.iv = Assert.notEmpty(iv, "Initialization Vector cannot be null or empty.");
        return this;
    }

    @Override
    public byte[] getIv() {
        return this.iv;
    }
}
