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
import io.jsonwebtoken.security.DecryptAeadRequest;

import javax.crypto.SecretKey;
import java.io.InputStream;

/**
 * @since 0.12.0
 */
public class DefaultDecryptAeadRequest extends DefaultAeadRequest implements DecryptAeadRequest {

    private final byte[] TAG;

    public DefaultDecryptAeadRequest(InputStream payload, SecretKey key, InputStream aad, byte[] iv, byte[] tag) {
        super(payload, null, null, key, aad,
                Assert.notEmpty(iv, "Initialization Vector cannot be null or empty."));
        this.TAG = Assert.notEmpty(tag, "AAD Authentication Tag cannot be null or empty.");
    }

    @Override
    public byte[] getDigest() {
        return this.TAG;
    }
}
