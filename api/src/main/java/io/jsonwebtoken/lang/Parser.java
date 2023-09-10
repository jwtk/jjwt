package io.jsonwebtoken.lang;

public interface Parser<I, O> {

    O parse(I input);

}
