package io.jsonwebtoken.impl.lang;

import java.net.URI;

public class UriStringConverter implements Converter<URI, String> {

    @Override
    public String applyTo(URI uri) {
        return uri.toString();
    }

    @Override
    public URI applyFrom(String s) {
        try {
            return URI.create(s);
        } catch (Exception e) {
            String msg = "Unable to convert String value '" + s + "' to URI instance: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
    }
}
