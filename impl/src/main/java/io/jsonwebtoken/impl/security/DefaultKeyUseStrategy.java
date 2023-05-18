/*
 * Copyright (C) 2022 jsonwebtoken.io
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

public class DefaultKeyUseStrategy implements KeyUseStrategy {

    static final KeyUseStrategy INSTANCE = new DefaultKeyUseStrategy();

    // values from https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2
    private static final String SIGNATURE = "sig";
    private static final String ENCRYPTION = "enc";

    @Override
    public String toJwkValue(KeyUsage usage) {

        // states 2, 3, 4
        if (usage.isKeyEncipherment() || usage.isDataEncipherment() || usage.isKeyAgreement()) {
            return ENCRYPTION;
        }

        // states 0, 1, 5, 6
        if (usage.isDigitalSignature() || usage.isNonRepudiation() || usage.isKeyCertSign() || usage.isCRLSign()) {
            return SIGNATURE;
        }

        // We don't need to check for encipherOnly (7) and decipherOnly (8) because per
        // [RFC 5280, Section 4.2.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3),
        // those two states are only relevant when keyAgreement (4) is true, and that is covered in the first
        // conditional above

        return null; //can't infer
    }
}
