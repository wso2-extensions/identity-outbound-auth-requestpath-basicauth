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

package org.wso2.carbon.identity.application.authenticator.requestpath.basicauth.internal;

import org.mockito.Mock;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.core.service.RealmService;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertNotNull;

public class BasicAuthRequestPathAuthenticatorServiceComponentTest extends PowerMockIdentityBaseTest {

    private BasicAuthRequestPathAuthenticatorServiceComponent basicAuthRequestPathAuthenticatorServiceComponent;

    @Mock
    RealmService mockRealmService;

    @Mock
    ComponentContext mockComponentContext;

    @BeforeTest
    public void setup() {
        initMocks(this);
        basicAuthRequestPathAuthenticatorServiceComponent = new BasicAuthRequestPathAuthenticatorServiceComponent();
    }

    @Test
    public void testSetRealmService() throws Exception {
        basicAuthRequestPathAuthenticatorServiceComponent.setRealmService(mockRealmService);
        assertNotNull(BasicAuthRequestPathAuthenticatorServiceComponent.getRealmService());
    }

    @Test
    public void testDeactivate() throws Exception {
        basicAuthRequestPathAuthenticatorServiceComponent.deactivate(mockComponentContext);
    }

    @Test
    public void testUnsetRealmService() throws Exception {
        basicAuthRequestPathAuthenticatorServiceComponent.unsetRealmService(mockRealmService);
    }
}