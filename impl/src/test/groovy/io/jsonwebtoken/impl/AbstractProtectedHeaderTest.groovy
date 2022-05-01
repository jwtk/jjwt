package io.jsonwebtoken.impl

import org.junit.Test

import static org.junit.Assert.assertEquals

class AbstractProtectedHeaderTest {

    @Test
    void x509UrlTest() {
        def header = new DefaultJwsHeader() // extends AbstractProtectedHeader
        URI uri = URI.create('https://google.com')
        header.setX509Url(uri)
        assertEquals uri, header.getX509Url()
    }

    @Test
    void x509UrlStringTest() { //test canonical/idiomatic conversion
        def header = new DefaultJwsHeader()
        String url = 'https://google.com'
        URI uri = URI.create(url)
        header.put('x5u', url)
        assertEquals url, header.get('x5u')
        assertEquals uri, header.getX509Url()
    }
}
