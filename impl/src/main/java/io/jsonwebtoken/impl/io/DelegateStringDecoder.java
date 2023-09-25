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

import java.io.InputStream;

@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated //TODO: delete when deleting JwtParserBuilder#base64UrlDecodeWith
public class DelegateStringDecoder implements Decoder<CharSequence, byte[]> {

    private final Decoder<String, byte[]> delegate;

    public DelegateStringDecoder(Decoder<String, byte[]> delegate) {
        this.delegate = Assert.notNull(delegate, "delegate cannot be null.");
    }

    @Override
    public byte[] decode(CharSequence charSequence) throws DecodingException {
        return delegate.decode(charSequence.toString());
    }

    @Override
    public InputStream wrap(InputStream in) {
        return delegate.wrap(in);
    }
}
