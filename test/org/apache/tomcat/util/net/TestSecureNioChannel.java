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

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLSession;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/*
 * Tests for the tracking of pending handshake wraps in SecureNioChannel. If the
 * needHandshakeWrap flag is left set when it should have been cleared, the
 * next time the SSLEngine requests a wrap while there is outbound data waiting
 * to be written the connection fails with a "There is already handshake data
 * waiting to be wrapped" IOException.
 */
public class TestSecureNioChannel {

    private static final byte[] DATA = "Tomcat".getBytes(StandardCharsets.ISO_8859_1);

    private ServerSocketChannel server;
    private SocketChannel client;
    private SocketChannel accepted;

    private SecureNioChannel channel;
    private TesterSSLEngine engine;


    @Before
    public void setUp() throws IOException {
        server = ServerSocketChannel.open();
        server.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        client = SocketChannel.open(server.getLocalAddress());
        accepted = server.accept();

        channel = new SecureNioChannel(new SocketBufferHandler(8192, 8192, false), new NioEndpoint());
        engine = new TesterSSLEngine();
    }


    @After
    public void tearDown() throws IOException {
        closeQuietly(accepted);
        closeQuietly(client);
        closeQuietly(server);
    }


    @Test
    public void testResetClearsNeedHandshakeWrap() throws Exception {
        // State left over from the previous connection that used this channel
        channel.needHandshakeWrap = true;

        channel.reset(accepted, null);

        Assert.assertFalse(channel.needHandshakeWrap);
    }


    @Test
    public void testGatheringWriteClearsNeedHandshakeWrap() throws Exception {
        channel.reset(accepted, null);
        startConnection();
        channel.needHandshakeWrap = true;

        long written = channel.write(new ByteBuffer[] { ByteBuffer.wrap(DATA) }, 0, 1);

        Assert.assertEquals(DATA.length, written);
        // The wrap() will have included any required handshake data
        Assert.assertFalse(channel.needHandshakeWrap);
    }


    @Test
    public void testWriteClearsNeedHandshakeWrap() throws Exception {
        channel.reset(accepted, null);
        startConnection();
        channel.needHandshakeWrap = true;

        int written = channel.write(ByteBuffer.wrap(DATA));

        Assert.assertEquals(DATA.length, written);
        Assert.assertFalse(channel.needHandshakeWrap);
    }


    /*
     * A channel is recycled after a connection in which a handshake wrap was
     * deferred. The new connection must not inherit that state and fail as soon
     * as its own TLS engine requests a wrap while outbound data is pending.
     */
    @Test
    public void testRecycledChannelDoesNotInheritPendingHandshakeWrap() throws Exception {
        // Previous connection deferred a handshake wrap and was then closed
        channel.needHandshakeWrap = true;

        // Channel is re-used for a new connection
        channel.reset(accepted, null);
        startConnection();

        // New connection: outbound data waiting and the engine needs to wrap
        setOutboundPending();
        client.write(ByteBuffer.wrap(DATA));

        // Must defer the wrap rather than fail the new connection
        int read = channel.read(ByteBuffer.allocate(8192));

        Assert.assertEquals(0, read);
        Assert.assertTrue(channel.needHandshakeWrap);
    }


    /*
     * A handshake wrap is deferred because outbound data is pending. The next
     * gathering write performs a wrap which includes the handshake data. A
     * subsequent request for a handshake wrap while outbound data is pending
     * must not be treated as a second pending handshake wrap.
     */
    @Test
    public void testGatheringWriteThenReadDoesNotFailConnection() throws Exception {
        channel.reset(accepted, null);
        startConnection();

        // Engine needs to wrap while outbound data is pending - wrap deferred
        setOutboundPending();
        client.write(ByteBuffer.wrap(DATA));
        Assert.assertEquals(0, channel.read(ByteBuffer.allocate(8192)));
        Assert.assertTrue(channel.needHandshakeWrap);

        // Gathering write - flushes pending data and wraps (incl. handshake data)
        long written = channel.write(new ByteBuffer[] { ByteBuffer.wrap(DATA) }, 0, 1);
        Assert.assertEquals(DATA.length, written);

        // Engine needs to wrap again while outbound data is pending
        setOutboundPending();
        client.write(ByteBuffer.wrap(DATA));

        // Must defer the wrap rather than fail the connection
        int read = channel.read(ByteBuffer.allocate(8192));

        Assert.assertEquals(0, read);
        Assert.assertTrue(channel.needHandshakeWrap);
    }


    private void startConnection() {
        // Simulate a connection with a completed initial handshake and an
        // empty network output buffer
        channel.sslEngine = engine;
        channel.handshakeComplete = true;
        channel.netOutBuffer.clear();
        channel.netOutBuffer.flip();
    }


    private void setOutboundPending() {
        // Simulate encrypted data that could not yet be written to the network
        channel.netOutBuffer.clear();
        channel.netOutBuffer.put(DATA);
        channel.netOutBuffer.flip();
        Assert.assertTrue(channel.getOutboundRemaining() > 0);
    }


    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException ignore) {
                // Ignore
            }
        }
    }


    /*
     * Minimal SSLEngine. Every unwrap() consumes all available network data and
     * reports that the engine needs to wrap (as happens, for example, when the
     * peer starts a renegotiation or requests a key update). Every wrap() copies
     * the application data to the network buffer unchanged.
     */
    private static class TesterSSLEngine extends SSLEngine {

        @Override
        public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
            int consumed = 0;
            for (int i = offset; i < offset + length; i++) {
                consumed += srcs[i].remaining();
                dst.put(srcs[i]);
            }
            return new SSLEngineResult(Status.OK, HandshakeStatus.NOT_HANDSHAKING, consumed, consumed);
        }

        @Override
        public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) {
            int consumed = src.remaining();
            src.position(src.limit());
            return new SSLEngineResult(Status.OK, HandshakeStatus.NEED_WRAP, consumed, 0);
        }

        @Override
        public Runnable getDelegatedTask() {
            return null;
        }

        @Override
        public void closeInbound() {
        }

        @Override
        public boolean isInboundDone() {
            return false;
        }

        @Override
        public void closeOutbound() {
        }

        @Override
        public boolean isOutboundDone() {
            return false;
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return new String[0];
        }

        @Override
        public String[] getEnabledCipherSuites() {
            return new String[0];
        }

        @Override
        public void setEnabledCipherSuites(String[] suites) {
        }

        @Override
        public String[] getSupportedProtocols() {
            return new String[0];
        }

        @Override
        public String[] getEnabledProtocols() {
            return new String[0];
        }

        @Override
        public void setEnabledProtocols(String[] protocols) {
        }

        @Override
        public SSLSession getSession() {
            return null;
        }

        @Override
        public void beginHandshake() {
        }

        @Override
        public HandshakeStatus getHandshakeStatus() {
            return HandshakeStatus.NOT_HANDSHAKING;
        }

        @Override
        public void setUseClientMode(boolean mode) {
        }

        @Override
        public boolean getUseClientMode() {
            return false;
        }

        @Override
        public void setNeedClientAuth(boolean need) {
        }

        @Override
        public boolean getNeedClientAuth() {
            return false;
        }

        @Override
        public void setWantClientAuth(boolean want) {
        }

        @Override
        public boolean getWantClientAuth() {
            return false;
        }

        @Override
        public void setEnableSessionCreation(boolean flag) {
        }

        @Override
        public boolean getEnableSessionCreation() {
            return false;
        }
    }
}
