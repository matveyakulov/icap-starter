package io.github.icap.spring.boot.client;

import io.github.icap.spring.boot.model.IcapResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the {@link DefaultIcapClient} wire behaviour against a minimal in-process ICAP server that
 * reads the request's ICAP header block and replies with a canned response. Preview is disabled in these
 * tests so the server can answer without having to participate in the 100-Continue handshake.
 */
class DefaultIcapClientTest {

    private FakeIcapServer server;

    @AfterEach
    void tearDown() throws IOException {
        if (server != null) {
            server.close();
        }
    }

    @Test
    void optionsReturnsParsedStatusAndHeaders() throws Exception {
        String response = "ICAP/1.0 200 OK\r\n"
                + "Methods: RESPMOD\r\n"
                + "ISTag: \"0001-abc\"\r\n"
                + "Allow: 204\r\n"
                + "Preview: 1024\r\n"
                + "Encapsulated: null-body=0\r\n"
                + "\r\n";
        server = new FakeIcapServer(response.getBytes(StandardCharsets.ISO_8859_1));

        IcapClient client = newClient();
        IcapResponse resp = client.options("avscan");

        assertThat(resp.getStatusCode()).isEqualTo(200);
        assertThat(resp.getHeaders().getFirst("Methods")).isEqualTo("RESPMOD");
        assertThat(resp.getIstag()).contains("\"0001-abc\"");
    }

    @Test
    void cleanContentYields204NoContent() throws Exception {
        String response = "ICAP/1.0 204 No Content\r\n"
                + "ISTag: \"clean\"\r\n"
                + "\r\n";
        server = new FakeIcapServer(response.getBytes(StandardCharsets.ISO_8859_1));

        IcapClient client = newClient();
        IcapResponse resp = client.scan("harmless text".getBytes(StandardCharsets.UTF_8), "note.txt");

        assertThat(resp.getStatusCode()).isEqualTo(204);
        assertThat(resp.isNoModificationsNeeded()).isTrue();
        assertThat(resp.isBlockedOrInfected()).isFalse();
    }

    @Test
    void infectedContentYields200WithReplacementBody() throws Exception {
        String httpResHdr = "HTTP/1.1 403 Forbidden\r\n"
                + "Content-Type: text/html\r\n"
                + "\r\n";
        String replacement = "<html><body>Blocked: malware detected</body></html>";
        String chunked = Integer.toHexString(replacement.length()) + "\r\n" + replacement + "\r\n0\r\n\r\n";

        String response = "ICAP/1.0 200 OK\r\n"
                + "ISTag: \"av-1\"\r\n"
                + "X-Infection-Found: Type=0; Resolution=2; Threat=EICAR-Test-File;\r\n"
                + "Encapsulated: res-hdr=0, res-body=" + httpResHdr.length() + "\r\n"
                + "\r\n"
                + httpResHdr
                + chunked;
        server = new FakeIcapServer(response.getBytes(StandardCharsets.ISO_8859_1));

        IcapClient client = newClient();
        IcapResponse resp = client.scan("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR".getBytes(StandardCharsets.UTF_8), "eicar.com");

        assertThat(resp.getStatusCode()).isEqualTo(200);
        assertThat(resp.isModified()).isTrue();
        assertThat(resp.isBlockedOrInfected()).isTrue();
        assertThat(resp.getInfectionFound()).isPresent();
        assertThat(new String(resp.getEncapsulatedBody(), StandardCharsets.UTF_8)).contains("malware detected");
    }

    /** Builds a client pointed at the fake server with preview disabled. */
    private DefaultIcapClient newClient() {
        return new DefaultIcapClient(
                "127.0.0.1", server.getPort(), "avscan",
                2000, 2000,
                /* previewEnabled */ false, 4096,
                /* allow204 */ true, /* tls */ false);
    }

    /**
     * A throwaway single-shot ICAP server: it accepts one connection, drains the request's ICAP header
     * block (up to the blank line) and writes back a pre-baked response.
     */
    static final class FakeIcapServer implements AutoCloseable {
        private final ServerSocket serverSocket;
        private final Thread thread;
        private final AtomicReference<Exception> failure = new AtomicReference<>();

        FakeIcapServer(byte[] response) throws IOException {
            this.serverSocket = new ServerSocket(0); // ephemeral port
            this.thread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    InputStream in = socket.getInputStream();
                    readUntilBlankLine(in);
                    OutputStream out = new BufferedOutputStream(socket.getOutputStream());
                    out.write(response);
                    out.flush();
                } catch (Exception e) {
                    failure.set(e);
                }
            }, "fake-icap-server");
            this.thread.setDaemon(true);
            this.thread.start();
        }

        int getPort() {
            return serverSocket.getLocalPort();
        }

        /** Reads bytes until an empty CRLF line is seen (end of the ICAP header block). */
        private static void readUntilBlankLine(InputStream in) throws IOException {
            int state = 0; // counts consecutive CR/LF forming the terminating CRLF CRLF
            int b;
            int lineLen = 0;
            while ((b = in.read()) != -1) {
                if (b == '\n') {
                    if (lineLen == 0) {
                        return; // blank line -> headers finished
                    }
                    lineLen = 0;
                } else if (b != '\r') {
                    lineLen++;
                }
                state++;
                if (state > 1_000_000) {
                    return; // safety valve
                }
            }
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
        }
    }
}
