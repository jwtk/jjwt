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
