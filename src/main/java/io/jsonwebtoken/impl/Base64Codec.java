/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Classes;

public class Base64Codec extends AbstractTextCodec {

    private static final boolean ANDROID = Classes.isAvailable("android.util.Base64");

    public String encode(byte[] data) {

        if (ANDROID) {
            int flags = android.util.Base64.NO_PADDING | android.util.Base64.NO_WRAP;
            return android.util.Base64.encodeToString(data, flags);
        }

        //else, assume standard JVM
        return javax.xml.bind.DatatypeConverter.printBase64Binary(data);
    }

    @Override
    public byte[] decode(String encoded) {

        if (ANDROID) {
            return android.util.Base64.decode(encoded, android.util.Base64.DEFAULT);
        }

        //else assume standard JVM:
        return javax.xml.bind.DatatypeConverter.parseBase64Binary(encoded);
    }

}
