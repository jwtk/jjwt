package io.jsonwebtoken;

import java.util.Date;

public interface Clock {
    Date now();
}
