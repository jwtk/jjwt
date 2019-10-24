package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.lang.UnknownClassException
import org.junit.Test

class LegacyServicesTest {

    @Test(expected = UnknownClassException)
    void serviceNotFoundTest() {
        // try to load a class that will NOT have any services, i.e. this test class.
        LegacyServices.loadFirst(LegacyServicesTest)
    }
}
