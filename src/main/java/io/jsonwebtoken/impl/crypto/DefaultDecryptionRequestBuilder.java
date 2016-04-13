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

public class DefaultDecryptionRequestBuilder implements DecryptionRequestBuilder {

    public static final String AAD_NEEDS_TAG_MSG = "If you specify additional authentication data during " +
                                                   "decryption, you must also specify the authentication tag " +
                                                   "computed during encryption.";

    public static final String TAG_NEEDS_AAD_MSG = "If you specify an authentication tag during decryption, you must " +
                                                   "also specify the additional authenticated data used " +
                                                   "during encryption.";
    private byte[] iv;
    private byte[] key;
    private byte[] ciphertext;
    private byte[] aad;
    private byte[] tag;

    @Override
    public DecryptionRequestBuilder setInitializationVector(byte[] iv) {
        this.iv = length(iv) > 0 ? iv : null;
        return this;
    }

    @Override
    public DecryptionRequestBuilder setKey(byte[] key) {
        this.key = length(key) > 0 ? key : null;
        return this;
    }

    public DecryptionRequestBuilder setCiphertext(byte[] ciphertext) {
        Assert.notEmpty(ciphertext, "Ciphertext cannot be null or empty.");
        this.ciphertext = ciphertext;
        return this;
    }

    @Override
    public DecryptionRequestBuilder setAdditionalAuthenticatedData(byte[] aad) {
        this.aad = length(aad) > 0 ? aad : null;
        return this;
    }

    @Override
    public DecryptionRequestBuilder setAuthenticationTag(byte[] tag) {
        this.tag = length(tag) > 0 ? tag : null;
        return this;
    }

    @Override
    public DecryptionRequest build() {
        Assert.notEmpty(ciphertext, "Ciphertext cannot be null or empty.");

        int aadLength = length(aad);
        int tagLength = length(tag);

        if (aadLength > 0 && tagLength == 0) {
            String msg = AAD_NEEDS_TAG_MSG;
            throw new IllegalArgumentException(msg);
        }
        if (tagLength > 0 && aadLength == 0) {
            String msg = TAG_NEEDS_AAD_MSG;
            throw new IllegalArgumentException(msg);
        }

        if (aadLength > 0 || tagLength > 0) {
            return new DefaultAuthenticatedDecryptionRequest(key, iv, ciphertext, aad, tag);
        }

        return new DefaultDecryptionRequest(key, iv, ciphertext);
    }

}
