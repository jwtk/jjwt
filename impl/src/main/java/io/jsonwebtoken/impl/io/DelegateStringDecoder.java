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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.io.InputStream;

@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated //TODO: delete when deleting JwtParserBuilder#base64UrlDecodeWith
public class DelegateStringDecoder implements Decoder<InputStream, InputStream> {

    private final Decoder<CharSequence, byte[]> delegate;

    public DelegateStringDecoder(Decoder<CharSequence, byte[]> delegate) {
        this.delegate = Assert.notNull(delegate, "delegate cannot be null.");
    }

    @Override
    public InputStream decode(InputStream in) throws DecodingException {
        try {
            byte[] data = Streams.bytes(in, "Unable to Base64URL-decode input.");
            data = delegate.decode(Strings.utf8(data));
            return Streams.of(data);
        } catch (Throwable t) {
            String msg = "Unable to Base64Url-decode InputStream: " + t.getMessage();
            throw new DecodingException(msg, t);
        }
    }
}
