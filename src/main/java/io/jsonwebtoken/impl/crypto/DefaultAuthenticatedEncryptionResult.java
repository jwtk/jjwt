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
package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;

public class DefaultAuthenticatedEncryptionResult extends DefaultEncryptionResult
        implements AuthenticatedEncryptionResult {

    private final byte[] tag;

    public DefaultAuthenticatedEncryptionResult(byte[] iv, byte[] ciphertext, byte[] tag) {
        super(iv, ciphertext);
        Assert.notEmpty(tag, "authentication tag cannot be null or empty.");
        this.tag = tag;
    }

    @Override
    public byte[] getAuthenticationTag() {
        return this.tag;
    }

    @Override
    public byte[] compact() {

        int ivLength = Arrays.length(iv);
        int ciphertextLength = Arrays.length(ciphertext);
        int tagLength = Arrays.length(tag);

        int outputLength = ivLength + ciphertextLength + tagLength;
        byte[] output = new byte[outputLength];

        //iv
        if (ivLength > 0) {
            output = new byte[outputLength];
            System.arraycopy(iv, 0, output, 0, ivLength);
        }

        //ciphertext
        System.arraycopy(ciphertext, 0, output, ivLength, ciphertextLength);

        //tag can never be empty based on the assertion in the constructor
        assert tagLength > 0;

        System.arraycopy(tag, 0, output, ivLength + ciphertextLength, tagLength);

        return output;
    }
}
