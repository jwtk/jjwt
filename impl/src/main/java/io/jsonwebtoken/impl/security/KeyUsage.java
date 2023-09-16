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
package io.jsonwebtoken.impl.security;

import java.security.cert.X509Certificate;

public final class KeyUsage {

    private static final boolean[] NO_FLAGS = new boolean[9];

    // Direct from X509Certificate#getKeyUsage() JavaDoc.  For an understand of when/how to use these
    // flags, read https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    private static final int
        digitalSignature = 0,
        nonRepudiation = 1,
        keyEncipherment = 2,
        dataEncipherment = 3,
        keyAgreement = 4,
        keyCertSign = 5,
        cRLSign = 6,
        encipherOnly = 7, //if keyAgreement, then only encipher data during key agreement
        decipherOnly = 8; //if keyAgreement, then only decipher data during key agreement

    private final boolean[] is; //for readability: i.e. is[nonRepudiation] simulates isNonRepudiation, etc.

    public KeyUsage(X509Certificate cert) {
        boolean[] arr = cert != null ? cert.getKeyUsage() : NO_FLAGS;
        this.is = arr != null ? arr : NO_FLAGS;
    }

    public boolean isDigitalSignature() {
        return is[digitalSignature];
    }

    public boolean isNonRepudiation() {
        return is[nonRepudiation];
    }

    public boolean isKeyEncipherment() {
        return is[keyEncipherment];
    }

    public boolean isDataEncipherment() {
        return is[dataEncipherment];
    }

    public boolean isKeyAgreement() {
        return is[keyAgreement];
    }

    public boolean isKeyCertSign() {
        return is[keyCertSign];
    }

    public boolean isCRLSign() {
        return is[cRLSign];
    }

    public boolean isEncipherOnly() {
        return is[encipherOnly];
    }

    public boolean isDecipherOnly() {
        return is[decipherOnly];
    }
}
