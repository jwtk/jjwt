package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

public class FormattedStringSupplier implements Supplier<String> {

    private final String msg;

    private final Object[] args;

    public FormattedStringSupplier(String msg, Object[] args) {
        this.msg = Assert.hasText(msg, "Message cannot be null or empty.");
        this.args = Assert.notEmpty(args, "Arguments cannot be null or empty.");
    }

    @Override
    public String get() {
        return String.format(this.msg, this.args);
    }
}
