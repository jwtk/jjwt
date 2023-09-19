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
package io.jsonwebtoken.impl;


import io.jsonwebtoken.Header;
import io.jsonwebtoken.lang.Strings;

import java.util.Map;

class DefaultTokenizedJwt implements TokenizedJwt {

    private final CharSequence protectedHeader;
    private final CharSequence payload;
    private final CharSequence digest;

    DefaultTokenizedJwt(CharSequence protectedHeader, CharSequence payload, CharSequence digest) {
        this.protectedHeader = protectedHeader;
        this.payload = payload;
        this.digest = digest;
    }

    @Override
    public CharSequence getProtected() {
        return this.protectedHeader;
    }

    @Override
    public CharSequence getPayload() {
        return this.payload;
    }

    @Override
    public CharSequence getDigest() {
        return this.digest;
    }

    @Override
    public Header createHeader(Map<String, ?> m) {
        if (Strings.hasText(getDigest())) {
            return new DefaultJwsHeader(m);
        }
        return new DefaultHeader(m);
    }
}
