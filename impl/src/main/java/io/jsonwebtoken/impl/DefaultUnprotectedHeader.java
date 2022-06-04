package io.jsonwebtoken.impl;

import io.jsonwebtoken.UnprotectedHeader;

import java.util.Map;

public class DefaultUnprotectedHeader extends AbstractHeader<UnprotectedHeader> implements UnprotectedHeader {

    public DefaultUnprotectedHeader() {
        super(AbstractHeader.FIELDS);
    }

    public DefaultUnprotectedHeader(Map<String, ?> values) {
        super(AbstractHeader.FIELDS, values);
    }
}
