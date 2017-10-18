/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.mockito.Mock;
import org.testng.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.requestpath.basicauth.internal.BasicAuthRequestPathAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

@PrepareForTest({User.class, IdentityTenantUtil.class, BasicAuthRequestPathAuthenticatorServiceComponent.class, MultitenantUtils.class, AuthenticatedUser.class, FrameworkUtils.class, IdentityUtil.class})
public class BasicAuthRequestPathAuthenticatorTest  extends PowerMockIdentityBaseTest{

    private BasicAuthRequestPathAuthenticator basicAuthRequestPathAuthenticator;
    private static final String AUTHENTICATOR_NAME = "BasicAuthRequestPathAuthenticator";
    private static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    private String dummyUserName = "testUsername";
    private String dummyPassword = "testPassword";
    private int dummyTenantId = -1234;
    private AuthenticatedUser authenticatedUser;

    @Mock
    Log mockLog;

    @Mock
    HttpServletRequest mockRequest;

    @Mock
    HttpServletResponse mockResponse;

    @Mock
    AuthenticationContext mockContext;

    BasicAuthRequestPathAuthenticator mockBasicAuthRequestPathAuthenticator = spy(new BasicAuthRequestPathAuthenticator());

    @Mock
    UserRealm mockUserRealm;

    @Mock
    UserStoreManager mockUserStoreManager;

    @Mock
    RealmService mockRealmService;

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
        basicAuthRequestPathAuthenticator = new BasicAuthRequestPathAuthenticator();
    }

    @DataProvider(name = "header")
    public Object[][] provideData() {
        return new Object[][]{
                {"testHeader", "testSecToken", false, true},
                {null, "testSecToken", true, true},
                {"Basic authenticator", "testSecToken", true, false},
                {"", null, false, false},
        };
    }

    @Test(dataProvider = "header")
    public void testCanHandle(String header, String sectoken, boolean expected, boolean isDebugEnabled) throws Exception {
        when(mockRequest.getHeader(AUTHORIZATION_HEADER_NAME)).thenReturn(header);
        when(mockRequest.getParameter("sectoken")).thenReturn(sectoken);

        assertEquals(basicAuthRequestPathAuthenticator.canHandle(mockRequest), expected,
                "Invalid can handle response for the request.");
    }

    @DataProvider(name = "checkCredentials")
    public Object[][] provideDataCheck() {
        String credentials1 = Base64.encode((":" + dummyPassword).getBytes());
        String credentials2 = Base64.encode((dummyUserName + ":").getBytes());
        String credentials3 = Base64.encode((":").getBytes());
        String testHeader = "testHeader ";
        return new Object[][]{
                {null, credentials1},
                {testHeader + credentials1, credentials1},
                {testHeader + credentials2, credentials2},
                {testHeader + credentials3, credentials3},
        };
    }

    @Test(dataProvider = "checkCredentials")
    public void processAuthenticationResponseTestCaseAuthenticationFailedException(String header, String credentials) throws AuthenticationFailedException {
        when(mockRequest.getHeader(AUTHORIZATION_HEADER_NAME)).thenReturn(header);
        when(mockRequest.getParameter("sectoken")).thenReturn(credentials);

        doThrow(new AuthenticationFailedException("username and password cannot be empty")).when
                (mockBasicAuthRequestPathAuthenticator).processAuthenticationResponse(mockRequest, mockResponse, mockContext);

        mockStatic(User.class);
        when(User.getUserFromUserName(dummyUserName)).thenReturn(new User());

        try {
            basicAuthRequestPathAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockContext);
        } catch (AuthenticationFailedException ex) {
            assertEquals(ex.getMessage(), "username and password cannot be empty");
        }
    }

    @Test
    public void processAuthenticationResponseTestCaseInvalidCredentialsException() throws AuthenticationFailedException, UserStoreException {
        when(mockRequest.getHeader(AUTHORIZATION_HEADER_NAME)).thenReturn(null);
        when(mockRequest.getParameter("sectoken")).thenReturn("dGVzdFVzZXJuYW1lOnRlc3RQYXNzd29yZA==");

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(dummyUserName)).thenReturn(dummyTenantId);

        doThrow(new InvalidCredentialsException("Authentication Failed")).when
                (mockBasicAuthRequestPathAuthenticator).processAuthenticationResponse(mockRequest, mockResponse, mockContext);

        mockStatic(BasicAuthRequestPathAuthenticatorServiceComponent.class);
        when(BasicAuthRequestPathAuthenticatorServiceComponent.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getTenantUserRealm(dummyTenantId)).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        mockStatic(User.class);
        mockStatic(MultitenantUtils.class);
        when(User.getUserFromUserName(dummyUserName)).thenReturn(new User());
        when(mockUserStoreManager.authenticate(MultitenantUtils.getTenantAwareUsername(dummyUserName), dummyPassword)).thenReturn(false);

        try {
            basicAuthRequestPathAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockContext);
        } catch (InvalidCredentialsException ex) {
            assertEquals(ex.getMessage(), "Authentication Failed");
        }
    }

    @DataProvider(name = "CheckAuthProperties")
    public Object[][] provideDataCheckAuthProp() {
        return new Object[][]{
                {null, true},
                {new HashMap<>(), false}
        };
    }

    @Test(dataProvider = "CheckAuthProperties")
    public void processAuthenticationResponseTestCaseAuthProperties(Object authPropMap , boolean expected) throws AuthenticationFailedException, UserStoreException {
        when(mockRequest.getHeader(AUTHORIZATION_HEADER_NAME)).thenReturn(null);
        when(mockRequest.getParameter("sectoken")).thenReturn("dGVzdFVzZXJuYW1lOnRlc3RQYXNzd29yZA==");

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(dummyUserName)).thenReturn(dummyTenantId);

        mockStatic(BasicAuthRequestPathAuthenticatorServiceComponent.class);
        when(BasicAuthRequestPathAuthenticatorServiceComponent.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getTenantUserRealm(dummyTenantId)).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        mockStatic(User.class);
        mockStatic(MultitenantUtils.class);
        when(User.getUserFromUserName(dummyUserName)).thenReturn(new User());
        when(mockUserStoreManager.authenticate(MultitenantUtils.getTenantAwareUsername(dummyUserName), dummyPassword)).thenReturn(true);
        when(MultitenantUtils.getTenantDomain(dummyUserName)).thenReturn("dummyTenantDomain");

        when(mockContext.getProperties()).thenReturn((HashMap)authPropMap);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn("primaryDomain");

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.prependUserStoreDomainToName(dummyUserName)).thenReturn(dummyUserName);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                authenticatedUser = (AuthenticatedUser) invocation.getArguments()[0];
                return null;
            }
        }).when(mockContext).setSubject(any(AuthenticatedUser.class));

        basicAuthRequestPathAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockContext);
        assertEquals(authenticatedUser.getAuthenticatedSubjectIdentifier(), dummyUserName);
    }

    @Test
    public void testGetContextIdentifier() throws Exception {
        assertNull(basicAuthRequestPathAuthenticator.getContextIdentifier(mockRequest));
    }

    @Test
    public void testGetFriendlyName() throws Exception {
        assertEquals(basicAuthRequestPathAuthenticator.getFriendlyName(), "basic-auth");
    }

    @Test
    public void testGetName() throws Exception {
        assertEquals(basicAuthRequestPathAuthenticator.getName(), AUTHENTICATOR_NAME);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}