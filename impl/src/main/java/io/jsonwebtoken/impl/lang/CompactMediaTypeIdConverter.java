/*
 * Copyright © 2022 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Strings;

public final class CompactMediaTypeIdConverter implements Converter<String, Object> {

    public static final Converter<String, Object> INSTANCE = new CompactMediaTypeIdConverter();

    private static final char FORWARD_SLASH = '/';

    private static final String APP_MEDIA_TYPE_PREFIX = "application" + FORWARD_SLASH;

    static String compactIfPossible(String cty) {
        Assert.hasText(cty, "Value cannot be null or empty.");
        if (Strings.startsWithIgnoreCase(cty, APP_MEDIA_TYPE_PREFIX)) {
            // per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10
            // we can only use the compact form if no other '/' exists in the string
            for (int i = cty.length() - 1; i >= APP_MEDIA_TYPE_PREFIX.length(); i--) {
                char c = cty.charAt(i);
                if (c == FORWARD_SLASH) {
                    return cty; // found another '/', can't compact, so just return unmodified
                }
            }
            // no additional '/' found, we can strip the prefix:
            return cty.substring(APP_MEDIA_TYPE_PREFIX.length());
        }
        return cty; // didn't start with 'application/', so we can't trim it - just return unmodified
    }

    @Override
    public Object applyTo(String s) {
        return compactIfPossible(s);
    }

    @Override
    public String applyFrom(Object o) {
        Assert.notNull(o, "Value cannot be null.");
        String s = Assert.isInstanceOf(String.class, o, "Value must be a string.");

        // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10:
        //
        //     A recipient using the media type value MUST treat it as if
        //     "application/" were prepended to any "cty" value not containing a
        //     '/'.
        //
        if (s.indexOf(FORWARD_SLASH) < 0) {
            s = APP_MEDIA_TYPE_PREFIX + s;
        }

        return s;
    }
}
