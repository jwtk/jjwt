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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;

class Payload {

    static final Payload EMPTY = new Payload(Bytes.EMPTY, null);

    private final String string;
    private final byte[] bytes;
    private final Claims claims;
    private final InputStream inputStream;
    private final boolean inputStreamEmpty;
    private final String contentType;
    private CompressionAlgorithm zip;

    Payload(Claims claims) {
        this(claims, null, null, null, null);
    }

    Payload(String content, String contentType) {
        this(null, content, null, null, contentType);
    }

    Payload(byte[] content, String contentType) {
        this(null, null, content, null, contentType);
    }

    Payload(InputStream inputStream, String contentType) {
        this(null, null, null, inputStream, contentType);
    }

    private Payload(Claims claims, String string, byte[] bytes, InputStream inputStream, String contentType) {
        this.claims = claims;
        this.string = Strings.clean(string);
        this.contentType = Strings.clean(contentType);
        InputStream in = inputStream;
        byte[] data = Bytes.nullSafe(bytes);
        if (Strings.hasText(this.string)) {
            data = Strings.utf8(this.string);
        }
        this.bytes = data;
        if (!Bytes.isEmpty(this.bytes)) {
            in = new ByteArrayInputStream(data);
        }
        this.inputStreamEmpty = in == null;
        this.inputStream = this.inputStreamEmpty ? new ByteArrayInputStream(Bytes.EMPTY) : in;
    }

    boolean isClaims() {
        return !Collections.isEmpty(this.claims);
    }

    Claims getRequiredClaims() {
        return Assert.notEmpty(this.claims, "Claims cannot be null or empty when calling this method.");
    }

    boolean isString() {
        return Strings.hasText(this.string);
    }

    String getContentType() {
        return this.contentType;
    }

    public void setZip(CompressionAlgorithm zip) {
        this.zip = zip;
    }

    boolean isCompressed() {
        return this.zip != null;
    }

    boolean isEmpty() {
        return !isClaims() && !isString() && Bytes.isEmpty(this.bytes) && this.inputStreamEmpty;
    }

    public OutputStream wrap(OutputStream out) {
        return this.zip != null ? zip.wrap(out) : out;
    }

    InputStream toInputStream() {
        // should only ever call this when claims don't exist:
        Assert.state(!isClaims(), "Claims exist, cannot convert to InputStream directly.");
        return this.inputStream;
    }
}
