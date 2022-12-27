package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

public final class CompactMediaTypeIdConverter implements Converter<String, Object> {

    public static final Converter<String, Object> INSTANCE = new CompactMediaTypeIdConverter();

    private static final String APP_MEDIA_TYPE_PREFIX = "application/";

    static String compactIfPossible(String cty) {
        Assert.hasText(cty, "Value cannot be null or empty.");
        if (Strings.startsWithIgnoreCase(cty, APP_MEDIA_TYPE_PREFIX)) {
            // per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10
            // we can only use the compact form if no other '/' exists in the string
            for (int i = cty.length() - 1; i >= APP_MEDIA_TYPE_PREFIX.length(); i--) {
                char c = cty.charAt(i);
                if (c == '/') {
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
        Assert.isInstanceOf(String.class, o, "Value must be a string.");
        String s = (String) o;
        return compactIfPossible(s);
    }
}
