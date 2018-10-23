package io.jsonwebtoken.io

import io.jsonwebtoken.lang.Classes
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.eq
import static org.easymock.EasyMock.expect
import static org.junit.Assert.*
import static org.powermock.api.easymock.PowerMock.mockStatic
import static org.powermock.api.easymock.PowerMock.replay
import static org.powermock.api.easymock.PowerMock.verify

@RunWith(PowerMockRunner.class)
@PrepareForTest([Classes])
class AndroidOrgJsonSerializerTest {

    @Test
    void testJSONStringNotAvailable() {

        mockStatic(Classes)

        expect(Classes.isAvailable(eq('org.json.JSONString'))).andReturn(false)

        replay Classes

        assertFalse OrgJsonSerializer.isJSONString('foo')

        verify Classes
    }

}
