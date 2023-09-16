/*
 * Copyright © 2020 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

import java.net.URI;

public class UriStringConverter implements Converter<URI, String> {

    @Override
    public String applyTo(URI uri) {
        Assert.notNull(uri, "URI cannot be null.");
        return uri.toString();
    }

    @Override
    public URI applyFrom(String s) {
        Assert.hasText(s, "URI string cannot be null or empty.");
        try {
            return URI.create(s);
        } catch (Exception e) {
            String msg = "Unable to convert String value '" + s + "' to URI instance: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
    }
}
