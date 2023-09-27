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

import java.util.Map;

class DefaultTokenizedJwe extends DefaultTokenizedJwt implements TokenizedJwe {

    private final CharSequence encryptedKey;
    private final CharSequence iv;

    DefaultTokenizedJwe(CharSequence protectedHeader, CharSequence body, CharSequence digest,
                        CharSequence encryptedKey, CharSequence iv) {
        super(protectedHeader, body, digest);
        this.encryptedKey = encryptedKey;
        this.iv = iv;
    }

    @Override
    public CharSequence getEncryptedKey() {
        return this.encryptedKey;
    }

    @Override
    public CharSequence getIv() {
        return this.iv;
    }

    @Override
    public Header createHeader(Map<String, ?> m) {
        return new DefaultJweHeader(m);
    }
}
