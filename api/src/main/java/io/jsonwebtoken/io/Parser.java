package io.jsonwebtoken.io;

public interface Parser<T> {

    T parse(String input);

}
