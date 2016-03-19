package io.jsonwebtoken;

import java.util.Date;

public class DefaultClock implements Clock {
    @Override
    public Date now() {
        return new Date();
    }
}
