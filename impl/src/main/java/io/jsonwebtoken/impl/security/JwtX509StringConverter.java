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

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.SecurityException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class JwtX509StringConverter implements Converter<X509Certificate, String> {

    public static final JwtX509StringConverter INSTANCE = new JwtX509StringConverter();

    // Returns a Base64 encoded (NOT Base64Url encoded) string of the cert's encoded byte array per
    // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6
    // https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.8
    // https://www.rfc-editor.org/rfc/rfc7517.html#section-4.7
    @Override
    public String applyTo(X509Certificate cert) {
        Assert.notNull(cert, "X509Certificate cannot be null.");
        byte[] der;
        try {
            der = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            String msg = "Unable to access X509Certificate encoded bytes necessary to perform DER " +
                    "Base64-encoding. Certificate: {" + cert + "}. Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
        if (Bytes.isEmpty(der)) {
            String msg = "X509Certificate encoded bytes cannot be null or empty.  Certificate: {" + cert + "}.";
            throw new IllegalArgumentException(msg);
        }
        return Encoders.BASE64.encode(der);
    }

    // visible for testing
    protected X509Certificate toCert(final byte[] der) throws SecurityException {
        return new JcaTemplate("X.509").generateX509Certificate(der);
    }

    @Override
    public X509Certificate applyFrom(String s) {
        Assert.hasText(s, "X.509 Certificate encoded string cannot be null or empty.");
        try {
            byte[] der = Decoders.BASE64.decode(s); //RFC requires Base64, not Base64Url
            return toCert(der);
        } catch (Exception e) {
            String msg = "Unable to convert Base64 String '" + s + "' to X509Certificate instance. Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
    }
}
