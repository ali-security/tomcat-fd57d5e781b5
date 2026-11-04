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
package org.apache.tomcat.util.net;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.UUID;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.core.AprLifecycleListener;
import org.apache.coyote.http11.Http11AprProtocol;
import org.apache.tomcat.jni.Library;

/**
 * Tests for the checks applied by the APR/Native connector to the directory in which a Unix Domain Socket is created.
 * The socket is created with permissions determined by the process umask and only then are the configured permissions
 * applied. The parent directory therefore has to restrict access to the socket during that window.
 */
@SuppressWarnings("deprecation")
public class TestAprEndpointUnixDomainSocket {

    private static final String SOCKET_NAME = "t.sock";

    private Path baseDir;
    private Http11AprProtocol protocol;
    private AprEndpoint endpoint;


    @BeforeClass
    public static void checkAprUnixDomainSocketSupport() {
        Assume.assumeTrue("POSIX file system required",
                FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        // Triggers initialisation of the APR/Native library
        new AprLifecycleListener();
        Assume.assumeTrue("APR/Native library not available", AprLifecycleListener.isAprAvailable());
        Assume.assumeTrue("APR/Native library does not support Unix Domain Sockets", Library.APR_HAVE_UNIX);
    }


    @Before
    public void setUp() throws Exception {
        // Use a short path as Unix Domain Socket paths are limited to ~108 bytes
        baseDir = Files.createTempDirectory("uds-");
        endpoint = new AprEndpoint();
        // The protocol provides the handler required by the endpoint
        protocol = new Http11AprProtocol(endpoint);
    }


    @After
    public void tearDown() throws Exception {
        try {
            endpoint.destroy();
        } finally {
            delete(baseDir);
        }
    }


    @Test
    public void testParentCreatedWithDerivedPermissions() throws Exception {
        Path parent = baseDir.resolve("a").resolve("b");
        Path socket = parent.resolve(SOCKET_NAME);
        Assert.assertTrue(protocol.setProperty("unixDomainSocketPath", socket.toString()));
        Assert.assertTrue(protocol.setProperty("unixDomainSocketPathPermissions", "rw-rw----"));

        endpoint.init();

        Assert.assertTrue(Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS));
        // Execute added for owner and group, group write removed
        Assert.assertEquals(PosixFilePermissions.fromString("rwxr-x---"),
                Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS));
        Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
        Assert.assertEquals(PosixFilePermissions.fromString("rw-rw----"),
                Files.getPosixFilePermissions(socket, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testParentCreatedWithDerivedPermissionsWorldReadable() throws Exception {
        Path parent = baseDir.resolve("a");
        Path socket = parent.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(socket.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-rw-rw-");

        endpoint.init();

        // Group and other write must never be granted on the parent by default
        Assert.assertEquals(PosixFilePermissions.fromString("rwxr-xr-x"),
                Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS));
        Assert.assertEquals(PosixFilePermissions.fromString("rw-rw-rw-"),
                Files.getPosixFilePermissions(socket, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testParentCreatedWithExplicitPermissions() throws Exception {
        Path parent = baseDir.resolve("a");
        Path socket = parent.resolve(SOCKET_NAME);
        Assert.assertTrue(protocol.setProperty("unixDomainSocketPath", socket.toString()));
        Assert.assertTrue(protocol.setProperty("unixDomainSocketPathPermissions", "rw-rw----"));
        Assert.assertTrue(protocol.setProperty("unixDomainSocketParentPermissions", "rwx--x---"));
        Assert.assertEquals("rwx--x---", endpoint.getUnixDomainSocketParentPermissions());

        endpoint.init();

        Assert.assertEquals(PosixFilePermissions.fromString("rwx--x---"),
                Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS));
        Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testExistingParentWithMatchingPermissions() throws Exception {
        Path parent = createParent("rwx------");
        Path socket = parent.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(socket.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-------");

        endpoint.init();

        Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
        Assert.assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(socket, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testExistingParentWithMoreRestrictivePermissions() throws Exception {
        Path parent = createParent("rwx------");
        Path socket = parent.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(socket.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-rw-rw-");

        endpoint.init();

        Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
    }


    /*
     * Exploit: the socket is placed in a directory any local user can traverse (and write to). During the window
     * between socket creation and the configured permissions being applied, other users can connect.
     */
    @Test
    public void testExistingParentWithLaxPermissionsRejected() throws Exception {
        Path parent = createParent("rwxrwxrwx");
        Path socket = parent.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(socket.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-------");

        assertInitFails(IllegalStateException.class);

        Assert.assertFalse(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
        // Existing directory must not have been modified
        Assert.assertEquals(PosixFilePermissions.fromString("rwxrwxrwx"),
                Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testExistingParentWithLaxExplicitPermissionsRejected() throws Exception {
        Path parent = createParent("rwxr-x---");
        Path socket = parent.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(socket.toString());
        endpoint.setUnixDomainSocketParentPermissions("rwx------");

        assertInitFails(IllegalStateException.class);

        Assert.assertFalse(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testExistingParentWithLaxPermissionsChecksSkipped() throws Exception {
        Path parent = createParent("rwxrwxrwx");
        Path socket = parent.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(socket.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        // Explicitly opt out of the parent directory checks
        endpoint.setUnixDomainSocketParentPermissions("");

        endpoint.init();

        Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testNoPermissionsConfigured() throws Exception {
        Path parent = createParent("rwxrwxrwx");
        Path socket = parent.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(socket.toString());

        endpoint.init();

        Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
    }


    /*
     * Exploit: the parent directory is replaced with a symbolic link to a directory of the attacker's choosing.
     */
    @Test
    public void testParentSymbolicLinkRejected() throws Exception {
        Path target = createParent("rwx------");
        Path link = baseDir.resolve("link");
        Files.createSymbolicLink(link, target);
        Path socket = link.resolve(SOCKET_NAME);
        endpoint.setUnixDomainSocketPath(socket.toString());
        endpoint.setUnixDomainSocketPathPermissions("rw-------");

        assertInitFails(Exception.class);

        Assert.assertFalse(Files.exists(target.resolve(SOCKET_NAME), LinkOption.NOFOLLOW_LINKS));
    }


    /*
     * Exploit: the parent directory is pre-created by another user who therefore controls access to it. The test
     * process can't change file ownership so use the system temporary directory, which is expected to be owned by
     * root.
     */
    @Test
    public void testParentOwnerMismatchRejected() throws Exception {
        Path parent = getForeignOwnedDirectory();
        Path socket = parent.resolve("uds-" + UUID.randomUUID().toString().substring(0, 8) + ".sock");
        endpoint.setUnixDomainSocketPath(socket.toString());
        // Ensure the permission check passes so the owner check is reached
        endpoint.setUnixDomainSocketParentPermissions("rwxrwxrwx");

        try {
            assertInitFails(IllegalStateException.class);
            Assert.assertFalse(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
        } finally {
            Files.deleteIfExists(socket);
        }
    }


    @Test
    public void testParentOwnerExpected() throws Exception {
        Path parent = getForeignOwnedDirectory();
        String owner = Files.getOwner(parent, LinkOption.NOFOLLOW_LINKS).getName();
        Path socket = parent.resolve("uds-" + UUID.randomUUID().toString().substring(0, 8) + ".sock");
        endpoint.setUnixDomainSocketPath(socket.toString());
        endpoint.setUnixDomainSocketParentPermissions("rwxrwxrwx");
        Assert.assertTrue(protocol.setProperty("unixDomainSocketParentOwner", owner));
        Assert.assertEquals(owner, endpoint.getUnixDomainSocketParentOwner());

        try {
            endpoint.init();
            Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
        } finally {
            endpoint.destroy();
            Files.deleteIfExists(socket);
        }
    }


    @Test
    public void testParentOwnerChecksSkipped() throws Exception {
        Path parent = getForeignOwnedDirectory();
        Path socket = parent.resolve("uds-" + UUID.randomUUID().toString().substring(0, 8) + ".sock");
        endpoint.setUnixDomainSocketPath(socket.toString());
        endpoint.setUnixDomainSocketParentPermissions("rwxrwxrwx");
        // Explicitly opt out of the owner check
        endpoint.setUnixDomainSocketParentOwner("");

        try {
            endpoint.init();
            Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
        } finally {
            endpoint.destroy();
            Files.deleteIfExists(socket);
        }
    }


    private Path createParent(String permissions) throws IOException {
        Path parent = Files.createDirectory(baseDir.resolve("parent-" + permissions.replace('-', '_')));
        // Not subject to the umask
        Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString(permissions));
        return parent;
    }


    private static Path getForeignOwnedDirectory() throws IOException {
        Path tmp = Paths.get(System.getProperty("java.io.tmpdir")).toAbsolutePath();
        Assume.assumeTrue(Files.isDirectory(tmp, LinkOption.NOFOLLOW_LINKS));
        String owner = Files.getOwner(tmp, LinkOption.NOFOLLOW_LINKS).getName();
        Assume.assumeFalse("Temporary directory is owned by the current user",
                owner.equals(System.getProperty("user.name")));
        Assume.assumeTrue("Temporary directory is not writable", Files.isWritable(tmp));
        return tmp;
    }


    private void assertInitFails(Class<? extends Exception> expected) {
        try {
            endpoint.init();
        } catch (Exception e) {
            Assert.assertTrue("Unexpected exception type: " + e, expected.isInstance(e));
            return;
        }
        Assert.fail("Endpoint initialisation should have failed");
    }


    private static void delete(Path dir) throws IOException {
        if (dir == null || !Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path d, IOException exc) throws IOException {
                Files.delete(d);
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
