/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.realm;

import java.net.InetAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;

import org.apache.tomcat.unittest.TesterContext;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

/*
 * When the realm checks the credentials by binding to the directory as the user, a simple bind must always be used,
 * whatever authentication mechanism is configured for the realm's own connection to the directory. Otherwise, with a
 * mechanism such as "none" the bind is anonymous, the password is never checked and any password is accepted.
 */
@RunWith(Parameterized.class)
public class TestJNDIRealmBindAsUser {

    private static final String USER_PATTERN = "cn={0},ou=people,dc=example,dc=com";
    private static final String USER_SEARCH = "cn={0}";
    private static final String USER_BASE = "ou=people,dc=example,dc=com";

    private static final String USERNAME = "test";
    private static final String PASSWORD = "test";

    private static InMemoryDirectoryServer ldapServer;

    @Parameterized.Parameters(name = "{index}: authentication[{0}], userPattern[{1}], userSearch[{2}], poolSize[{4}]")
    public static Collection<Object[]> parameters() {
        List<Object[]> parameterSets = new ArrayList<>();
        for (String authentication : new String[] { null, "none", "simple" }) {
            for (int poolSize : new int[] { 1, 4 }) {
                parameterSets.add(
                        new Object[] { authentication, USER_PATTERN, null, null, Integer.valueOf(poolSize) });
                parameterSets.add(
                        new Object[] { authentication, null, USER_SEARCH, USER_BASE, Integer.valueOf(poolSize) });
            }
        }
        return parameterSets;
    }


    @Parameter(0)
    public String authentication;
    @Parameter(1)
    public String realmConfigUserPattern;
    @Parameter(2)
    public String realmConfigUserSearch;
    @Parameter(3)
    public String realmConfigUserBase;
    @Parameter(4)
    public int poolSize;


    @Test
    public void testValidPassword() throws Exception {
        JNDIRealm realm = createRealm();
        try {
            // If using pooling, simply try more to see what happens
            for (int i = 0; i <= poolSize; i++) {
                Principal p = realm.authenticate(USERNAME, PASSWORD);
                Assert.assertNotNull(p);
                Assert.assertEquals(USERNAME, p.getName());
            }
        } finally {
            realm.stop();
        }
    }


    @Test
    public void testInvalidPassword() throws Exception {
        JNDIRealm realm = createRealm();
        try {
            for (int i = 0; i <= poolSize; i++) {
                Assert.assertNull(realm.authenticate(USERNAME, "wrong"));
            }
        } finally {
            realm.stop();
        }
    }


    @Test
    public void testEmptyPassword() throws Exception {
        JNDIRealm realm = createRealm();
        try {
            Assert.assertNull(realm.authenticate(USERNAME, ""));
        } finally {
            realm.stop();
        }
    }


    @Test
    public void testInvalidPasswordAfterValidPassword() throws Exception {
        JNDIRealm realm = createRealm();
        try {
            for (int i = 0; i <= poolSize; i++) {
                Assert.assertNotNull(realm.authenticate(USERNAME, PASSWORD));
                Assert.assertNull(realm.authenticate(USERNAME, "wrong"));
            }
        } finally {
            realm.stop();
        }
    }


    private JNDIRealm createRealm() throws Exception {
        JNDIRealm realm = new JNDIRealm();
        realm.setContainer(new TesterContext());

        realm.setConnectionURL("ldap://localhost:" + ldapServer.getListenPort());
        realm.setAuthentication(authentication);
        realm.setUserPattern(realmConfigUserPattern);
        realm.setUserSearch(realmConfigUserSearch);
        realm.setUserBase(realmConfigUserBase);
        realm.setConnectionPoolSize(poolSize);

        realm.start();

        return realm;
    }


    @BeforeClass
    public static void createLDAP() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        InetAddress localhost = InetAddress.getByName("localhost");
        InMemoryListenerConfig listenerConfig =
                new InMemoryListenerConfig("localListener", localhost, 0, null, null, null);
        config.setListenerConfigs(listenerConfig);
        ldapServer = new InMemoryDirectoryServer(config);

        ldapServer.startListening();

        try (LDAPConnection conn = ldapServer.getConnection()) {

            AddRequest addBase = new AddRequest(
                    "dn: dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: domain",
                    "dc: example");
            LDAPResult result = conn.processOperation(addBase);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());

            AddRequest addPeople = new AddRequest(
                    "dn: ou=people,dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: organizationalUnit");
            result = conn.processOperation(addPeople);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());

            AddRequest addUserTest = new AddRequest(
                    "dn: cn=" + USERNAME + ",ou=people,dc=example,dc=com",
                    "objectClass: top",
                    "objectClass: person",
                    "objectClass: organizationalPerson",
                    "cn: " + USERNAME,
                    "sn: Test",
                    "userPassword: " + PASSWORD);
            result = conn.processOperation(addUserTest);
            Assert.assertEquals(ResultCode.SUCCESS, result.getResultCode());
        }
    }


    @AfterClass
    public static void destroyLDAP() {
        ldapServer.shutDown(true);
    }
}
