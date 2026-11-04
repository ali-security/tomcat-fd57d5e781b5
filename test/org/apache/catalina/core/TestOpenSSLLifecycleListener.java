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
package org.apache.catalina.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.net.openssl.OpenSSLStatus;

public class TestOpenSSLLifecycleListener {

    /*
     * FIPS mode is requested but the OpenSSL library used for the tests does not provide it. Initialisation of the
     * server must fail rather than continue without FIPS mode.
     */
    @Test
    public void testFIPSModeRequestedNotAvailableServerInitFails() throws Exception {
        Assume.assumeTrue(JreCompat.isJre22Available());

        Path tmpDir = Paths.get(System.getProperty("tomcat.test.temp", "output/tmp"));
        Files.createDirectories(tmpDir);

        Tomcat tomcat = new Tomcat();
        Path base = Files.createTempDirectory(tmpDir, "tomcat-fips-");
        tomcat.setBaseDir(base.toAbsolutePath().toString());
        tomcat.setPort(0);

        StandardServer server = (StandardServer) tomcat.getServer();
        OpenSSLLifecycleListener listener = new OpenSSLLifecycleListener();
        listener.setFIPSMode("on");
        // The FFM based OpenSSL support must be present for the FIPS mode setting to be accepted
        Assume.assumeTrue("on".equals(listener.getFIPSMode()));
        server.addLifecycleListener(listener);

        try {
            LifecycleException initFailure = null;
            try {
                tomcat.init();
            } catch (LifecycleException e) {
                initFailure = e;
            }

            if (initFailure == null) {
                // The only acceptable reason for a successful initialisation is that FIPS mode is active
                Assert.assertTrue("Server initialised with FIPS mode requested but not active",
                        listener.isFIPSModeActive());
            } else {
                Assert.assertFalse(listener.isFIPSModeActive());
                Assert.assertEquals(LifecycleState.FAILED, server.getState());
                Throwable cause = initFailure.getCause();
                Assert.assertNotNull(cause);
                Assert.assertTrue(cause instanceof Error);
                Assert.assertEquals(OpenSSLLifecycleListener.sm.getString("openssllistener.initializeFIPSFailed"),
                        cause.getMessage());
                // The failed OpenSSL initialisation must have been cleaned up
                Assert.assertFalse(OpenSSLStatus.isInitialized());
            }
        } finally {
            try {
                tomcat.destroy();
            } catch (LifecycleException e) {
                // Ignore - the server may have failed to initialise
            }
            listener.setFIPSMode("off");
        }
    }


    /*
     * The OpenSSL library initialises without error but FIPS mode, which was requested, is not active. The listener
     * must signal a fatal error rather than allow the server to continue without FIPS mode.
     */
    @Test
    public void testFIPSModeRequestedNotActiveListenerThrowsError() {
        Assume.assumeTrue(JreCompat.isJre22Available());

        OpenSSLLifecycleListener listener = new OpenSSLLifecycleListener() {
            @Override
            public String getFIPSMode() {
                return "on";
            }

            @Override
            public boolean isFIPSModeActive() {
                return false;
            }
        };
        StandardServer server = new StandardServer();

        Error error = null;
        try {
            listener.lifecycleEvent(new LifecycleEvent(server, Lifecycle.BEFORE_INIT_EVENT, null));
        } catch (Error e) {
            error = e;
        }

        Assert.assertNotNull("FIPS mode requested but not active did not trigger an Error", error);
        Assert.assertEquals(OpenSSLLifecycleListener.sm.getString("openssllistener.initializeFIPSFailed"),
                error.getMessage());
        // The failed OpenSSL initialisation must have been cleaned up
        Assert.assertFalse(OpenSSLStatus.isInitialized());
    }
}
