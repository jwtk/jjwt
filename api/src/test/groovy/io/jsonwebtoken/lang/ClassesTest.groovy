package io.jsonwebtoken.lang;

import io.jsonwebtoken.lang.Classes;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.Timeout;

public class ClassesTest {

    @Rule public final ExpectedException thrown = ExpectedException.none();

    @Rule public final Timeout globalTimeout = new Timeout(10000);

    // Test written by Diffblue Cover.
    @Test
    public void newInstanceInputNullOutputIllegalArgumentException() {

        // Arrange
        final Class clazz = null;

        // Act
        thrown.expect(IllegalArgumentException.class);
        Classes.newInstance(clazz);

        // The method is not expected to return due to exception thrown
    }
}
