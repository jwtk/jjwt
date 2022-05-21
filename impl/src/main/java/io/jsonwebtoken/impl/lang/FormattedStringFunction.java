package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

public class FormattedStringFunction<T> implements Function<T, String> {

    private final String msg;

    public FormattedStringFunction(String msg) {
        this.msg = Assert.hasText(msg, "msg argument cannot be null or empty.");
    }

    @Override
    public String apply(T arg) {
        return String.format(msg, arg);
    }
}
