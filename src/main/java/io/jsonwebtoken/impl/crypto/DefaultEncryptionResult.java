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

import io.jsonwebtoken.lang.Assert;

import static io.jsonwebtoken.lang.Arrays.length;

public class DefaultEncryptionResult implements EncryptionResult {

    protected final byte[] iv;
    protected final byte[] ciphertext;

    public DefaultEncryptionResult(byte[] iv, byte[] ciphertext) {
        Assert.notEmpty(ciphertext, "ciphertext cannot be null or empty.");
        this.ciphertext = ciphertext;
        this.iv = iv;
    }

    @Override
    public byte[] getInitializationValue() {
        return this.iv;
    }

    @Override
    public byte[] getCiphertext() {
        return this.ciphertext;
    }

    @Override
    public byte[] compact() {

        byte[] output = ciphertext; //default

        int ivLength = length(iv);

        if (ivLength > 0) {

            int ciphertextLength = length(ciphertext);

            int outputLength = ivLength + ciphertextLength;

            output = new byte[outputLength];

            System.arraycopy(iv, 0, output, 0, ivLength);

            System.arraycopy(ciphertext, 0, output, ivLength, ciphertextLength);
        }

        return output;
    }

}
