package io.jsonwebtoken;

public interface Locator<H extends Header<H>, R> {

    R locate(H header);
}
