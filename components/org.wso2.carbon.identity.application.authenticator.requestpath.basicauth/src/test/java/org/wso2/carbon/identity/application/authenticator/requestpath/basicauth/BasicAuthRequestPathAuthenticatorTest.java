/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.requestpath.basicauth;

import org.apache.commons.logging.Log;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.AfterMethod;
import org.testng.Assert;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.DataProvider;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;

public class BasicAuthRequestPathAuthenticatorTest {

    private BasicAuthRequestPathAuthenticator  basicAuthRequestPathAuthenticator;
    private static final String AUTHENTICATOR_NAME = "BasicAuthRequestPathAuthenticator";
    private static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    private String debugMsg;

    @Mock
    Log mockLog;

    @Mock
    HttpServletRequest mockRequest;

    @DataProvider(name = "headerValue")
    public Object[][] provideData() {
        return new Object[][]{
                {"testHeader", "testSecToken", false, true},
                {null, "testSecToken", true,true},
                {"Basic authenticator", "testSecToken", true, false},
                {"", null, false, false},
        };
    }

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        basicAuthRequestPathAuthenticator = new BasicAuthRequestPathAuthenticator();
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test(dataProvider = "headerValue")
    public void testCanHandle(String header, String sectoken, boolean expected, boolean isDebugEnabled) throws Exception {

        mockLog = mock(Log.class);
        enableDebugLogs(mockLog, isDebugEnabled);
        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                debugMsg = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockLog).debug(anyString());

        when(mockRequest.getHeader(AUTHORIZATION_HEADER_NAME)).thenReturn(header);
        when(mockRequest.getParameter("sectoken")).thenReturn(sectoken);

        assertEquals(basicAuthRequestPathAuthenticator.canHandle(mockRequest),expected,
                "Invalid can handle response for the request.");

    }

    @Test
    public void testProcessAuthenticationResponse() throws Exception {

    }

    @Test
    public void testGetContextIdentifier() throws Exception {
        assertEquals(basicAuthRequestPathAuthenticator.getContextIdentifier(mockRequest), null);
    }

    @Test
    public void testGetFriendlyName() throws Exception {
        assertEquals(basicAuthRequestPathAuthenticator.getFriendlyName(), "basic-auth");
    }

    @Test
    public void testGetName() throws Exception {
        assertEquals(basicAuthRequestPathAuthenticator.getName(), AUTHENTICATOR_NAME);
    }

    private static void enableDebugLogs(final Log mockedLog, boolean isDebugEnabled) throws NoSuchFieldException, IllegalAccessException {

        when(mockedLog.isDebugEnabled()).thenReturn(isDebugEnabled);
        Field field = BasicAuthRequestPathAuthenticator.class.getDeclaredField("log");
        field.setAccessible(true);
        field.set(null, mockedLog);
    }

}