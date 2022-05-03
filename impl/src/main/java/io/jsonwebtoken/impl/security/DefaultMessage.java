package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Message;

class DefaultMessage implements Message {

    private final byte[] content;

    DefaultMessage(byte[] content) {
        Assert.notEmpty(content, "content byte array cannot be null or empty.");
        this.content = content;
    }

    @Override
    public byte[] getContent() {
        return content;
    }
}
