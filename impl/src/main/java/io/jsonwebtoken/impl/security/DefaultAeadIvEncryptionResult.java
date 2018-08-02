/*
 * Copyright (C) 2016 jsonwebtoken.io
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
import io.jsonwebtoken.security.AeadIvEncryptionResult;

/**
 * @since JJWT_RELEASE_VERSION
 */
class DefaultAeadIvEncryptionResult extends DefaultIvEncryptionResult implements AeadIvEncryptionResult {

    private final byte[] tag;

    DefaultAeadIvEncryptionResult(byte[] ciphertext, byte[] iv, byte[] tag) {
        super(ciphertext, iv);
        this.tag = Assert.notEmpty(tag, "authentication tag cannot be null or empty.");
    }

    @Override
    public byte[] getAuthenticationTag() {
        return this.tag;
    }

    @Override
    public byte[] compact() {
        byte[] output = new byte[iv.length + ciphertext.length + tag.length];
        System.arraycopy(iv, 0, output, 0, iv.length); // iv first
        System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length); // then ciphertext
        System.arraycopy(tag, 0, output, iv.length + ciphertext.length, tag.length); // finally tag
        return output;
    }
}
