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

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.lang.Strings;

class Payload {

    private String string;
    private byte[] bytes;
    private String contentType;

    Payload(String string, byte[] bytes, String contentType) {
        this.string = Strings.clean(string);
        this.bytes = Bytes.nullSafe(bytes);
        this.contentType = Strings.clean(contentType);
    }

    String getString() {
        return this.string;
    }

    String getContentType() {
        return this.contentType;
    }

    boolean isEmpty() {
        return !Strings.hasText(this.string) && Bytes.isEmpty(this.bytes);
    }

    byte[] toByteArray() {
        if (Bytes.isEmpty(this.bytes)) {
            if (!Strings.hasText(this.string)) {
                throw new IllegalStateException("Content is empty.");
            }
            this.bytes = Strings.utf8(this.string);
        }
        return this.bytes;
    }
}
