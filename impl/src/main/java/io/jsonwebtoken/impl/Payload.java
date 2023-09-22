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
    private final String contentType;

    private CompressionAlgorithm zip;

    Payload(String content, String contentType) {
        this(null, content, null, contentType);
    }

    Payload(byte[] content, String contentType) {
        this(null, null, content, contentType);
    }

    Payload(Claims claims, String contentType) {
        this(claims, null, null, contentType);
    }

    private Payload(Claims claims, String string, byte[] bytes, String contentType) {
        this.claims = claims;
        this.bytes = Bytes.nullSafe(bytes);
        this.string = Strings.clean(string);
        this.contentType = Strings.clean(contentType);
    }

    Claims getRequiredClaims() {
        return Assert.notEmpty(this.claims, "Claims cannot be null or empty when calling this method.");
    }

    String getString() {
        return this.string;
    }

    String getContentType() {
        return this.contentType;
    }

    public void setZip(CompressionAlgorithm zip) {
        this.zip = zip;
    }

    boolean isEmpty() {
        return Collections.isEmpty(this.claims) && Bytes.isEmpty(this.bytes) && !Strings.hasText(this.string);
    }

    public OutputStream wrap(OutputStream out) {
        return this.zip != null ? zip.wrap(out) : out;
    }

    boolean hasClaims() {
        return !Collections.isEmpty(this.claims);
    }

    InputStream toInputStream() {
        byte[] data = this.bytes;
        if (Bytes.isEmpty(data) && Strings.hasText(this.string)) {
            data = Strings.utf8(this.string);
        }
        return new ByteArrayInputStream(Bytes.nullSafe(data));
    }
}
