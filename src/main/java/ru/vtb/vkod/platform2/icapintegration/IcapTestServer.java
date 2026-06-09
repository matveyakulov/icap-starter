package ru.vtb.vkod.platform2.icapintegration;

import io.github.icap.spring.boot.model.IcapHeaders;
import io.github.icap.spring.boot.model.IcapStatus;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A small, dependency-free ICAP/1.0 (RFC 3507) <strong>server</strong> intended for use on a test stand:
 * point {@link io.github.icap.spring.boot.client.DefaultIcapClient DefaultIcapClient} (or any ICAP client,
 * e.g. a Squid proxy) at it and exercise the full request/response flow without needing a real
 * antivirus/DLP appliance.
 *
 * <p>ICAP is <em>not</em> HTTP, so this is deliberately a raw TCP listener rather than a Spring MVC
 * controller. It speaks the same wire format the bundled client produces, in reverse:</p>
 * <ul>
 *     <li><b>OPTIONS</b> &mdash; replies {@code 200 OK} advertising the supported methods, an {@code ISTag},
 *         {@code Allow: 204} and a {@code Preview} size.</li>
 *     <li><b>REQMOD / RESPMOD</b> &mdash; parses the {@code Encapsulated} header, reads the encapsulated HTTP
 *         header block(s) verbatim and the (chunked) body, honouring {@code Preview}/{@code 100 Continue}.
 *         It then applies a trivial verdict policy (see {@link Verdict}):
 *         <ul>
 *             <li>body contains the EICAR test signature &rarr; {@code 200 OK} with an
 *                 {@code X-Infection-Found} header and a replacement "blocked" message;</li>
 *             <li>otherwise &rarr; {@code 204 No Content} when the client offered {@code Allow: 204},
 *                 or an unmodified {@code 200 OK} echo of the original message.</li>
 *         </ul>
 *     </li>
 * </ul>
 *
 * <h2>Running it</h2>
 * <pre>{@code
 * // standalone (default port 1344):
 * java -cp target/classes ru.vtb.vkod.platform2.icapintegration.IcapTestServer
 * // or pick a port:
 * java -cp target/classes ru.vtb.vkod.platform2.icapintegration.IcapTestServer 13440
 * }</pre>
 *
 * <p>Or embed it (e.g. in an integration test):</p>
 * <pre>{@code
 * try (IcapTestServer server = new IcapTestServer(0)) { // 0 = ephemeral port
 *     server.start();
 *     int port = server.getPort();
 *     // ... point the client at localhost:port ...
 * }
 * }</pre>
 *
 * <p>This server is intentionally simple (one virtual thread per connection, no keep-alive accounting,
 * permissive parsing) and is <strong>not</strong> meant for production traffic.</p>
 */
public class IcapTestServer implements AutoCloseable {

    private static final byte[] CRLF = {'\r', '\n'};
    private static final String ICAP_VERSION = "ICAP/1.0";
    /** The standard, well-known EICAR antivirus test signature (harmless; triggers AV products). */
    private static final byte[] EICAR_SIGNATURE =
            ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
                    .getBytes(StandardCharsets.US_ASCII);

    private final int requestedPort;
    private final ExecutorService connectionPool;
    /** Changes whenever the "service state" changes; clients use it to invalidate caches. */
    private final String istag = "ICAP-TEST-" + Long.toHexString(System.currentTimeMillis());
    private final AtomicLong connectionCounter = new AtomicLong();

    /**
     * Controls the verdict the server returns: when {@code true} the scan "passes" (clean content is
     * answered with {@code 204}/{@code 200} echo); when {@code false} every request is treated as a failed
     * check and answered with a {@code 200 OK} "blocked" response carrying {@code X-Infection-Found}.
     * The EICAR test signature is always treated as infected regardless of this flag. Mutable so a stand can
     * flip the outcome between requests.
     */
    private volatile boolean checkPasses;

    private volatile ServerSocket serverSocket;
    private volatile Thread acceptThread;
    private volatile boolean running;

    /**
     * @param port the TCP port to bind, or {@code 0} to let the OS pick an ephemeral one
     *             (read it back with {@link #getPort()} after {@link #start()})
     */
    public IcapTestServer(int port) {
        this(port, true);
    }

    /**
     * @param port        the TCP port to bind, or {@code 0} for an ephemeral one
     * @param checkPasses initial verdict policy: {@code true} = scans pass (content reported clean),
     *                    {@code false} = scans fail (content reported infected/blocked)
     */
    public IcapTestServer(int port, boolean checkPasses) {
        this.requestedPort = port;
        this.checkPasses = checkPasses;
        // A small cached pool is plenty for a test stand: one daemon thread per active connection.
        this.connectionPool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "icap-test-server-conn");
            t.setDaemon(true);
            return t;
        });
    }

    /** @return whether scans currently pass (clean) or fail (blocked). */
    public boolean isCheckPasses() {
        return checkPasses;
    }

    /**
     * Switches the verdict policy at runtime.
     *
     * @param checkPasses {@code true} = report content clean, {@code false} = report content infected/blocked
     */
    public void setCheckPasses(boolean checkPasses) {
        this.checkPasses = checkPasses;
    }

    /** @return {@code true} while the server is accepting connections. */
    public boolean isRunning() {
        return running;
    }

    /**
     * Binds the listening socket and starts accepting connections on a background thread. Returns once the
     * socket is bound, so {@link #getPort()} is valid immediately afterwards.
     *
     * @throws IOException if the port cannot be bound
     */
    public synchronized void start() throws IOException {
        if (running) {
            return;
        }
        serverSocket = new ServerSocket(requestedPort);
        running = true;
        acceptThread = new Thread(this::acceptLoop, "icap-test-server-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        log("listening on port " + getPort() + " (ISTag=" + istag
                + ", checkPasses=" + checkPasses + ")");
    }

    /** @return the actual bound port (useful when constructed with port {@code 0}). */
    public int getPort() {
        ServerSocket s = serverSocket;
        if (s == null) {
            throw new IllegalStateException("server not started");
        }
        return s.getLocalPort();
    }

    /** Stops accepting connections and closes the listening socket. In-flight handlers finish on their own. */
    @Override
    public synchronized void close() {
        running = false;
        ServerSocket s = serverSocket;
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
                // best-effort
            }
        }
        connectionPool.shutdownNow();
        log("stopped");
    }

    // ---------------------------------------------------------------------
    // Accept loop
    // ---------------------------------------------------------------------

    private void acceptLoop() {
        while (running) {
            final Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                if (running) {
                    log("accept failed: " + e.getMessage());
                }
                return; // socket closed -> stop
            }
            long id = connectionCounter.incrementAndGet();
            connectionPool.submit(() -> handleConnection(socket, id));
        }
    }

    private void handleConnection(Socket socket, long id) {
        try (socket;
             BufferedInputStream in = new BufferedInputStream(socket.getInputStream());
             BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream())) {

            // One request per connection is enough for the bundled client (it does not keep-alive).
            // We still loop so clients that reuse the connection keep working until they close it.
            while (running) {
                boolean handled = handleOneExchange(in, out, id);
                if (!handled) {
                    break;
                }
            }
        } catch (IOException e) {
            log("conn#" + id + " I/O error: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------------
    // Request parsing + dispatch
    // ---------------------------------------------------------------------

    /**
     * Reads and answers a single ICAP exchange.
     *
     * @return {@code true} if a request was processed (the caller may try to read another), {@code false}
     *         if the peer closed the connection.
     */
    private boolean handleOneExchange(BufferedInputStream in, BufferedOutputStream out, long id) throws IOException {
        String requestLine = readLine(in);
        if (requestLine == null || requestLine.isEmpty()) {
            return false; // connection closed / nothing to read
        }

        // Request line: "<METHOD> icap://host:port/service ICAP/1.0"
        String[] parts = requestLine.split(" ");
        if (parts.length < 3 || !parts[2].startsWith("ICAP/")) {
            log("conn#" + id + " malformed request line: '" + requestLine + "'");
            writeSimpleResponse(out, IcapStatus.BAD_REQUEST);
            return false;
        }
        String method = parts[0].toUpperCase();

        IcapHeaders icapHeaders = readHeaders(in);
        log("conn#" + id + " " + method + " " + parts[1]);

        switch (method) {
            case "OPTIONS" -> handleOptions(out);
            case "REQMOD", "RESPMOD" -> handleModification(method, icapHeaders, in, out);
            default -> writeSimpleResponse(out, IcapStatus.METHOD_NOT_ALLOWED);
        }
        out.flush();
        return true;
    }

    /** Answers an OPTIONS request with this service's advertised capabilities. */
    private void handleOptions(BufferedOutputStream out) throws IOException {
        IcapHeaders headers = new IcapHeaders();
        headers.set("ISTag", quoted(istag));
        headers.set("Methods", "REQMOD, RESPMOD");
        headers.set("Service", "ICAP Test Server 1.0");
        headers.set("Max-Connections", "100");
        headers.set("Options-TTL", "3600");
        headers.set("Allow", "204");
        headers.set("Preview", "4096");
        headers.set("Encapsulated", "null-body=0");
        writeStatusLine(out, IcapStatus.OK);
        writeHeaders(out, headers);
        out.write(CRLF); // terminate header block; OPTIONS carries no body
    }

    /**
     * Handles REQMOD/RESPMOD: reads the encapsulated message, computes a verdict and writes the reply.
     */
    private void handleModification(String method, IcapHeaders icapHeaders,
                                    BufferedInputStream in, BufferedOutputStream out) throws IOException {
        String encapsulated = icapHeaders.getFirst("Encapsulated");
        if (encapsulated == null) {
            writeSimpleResponse(out, IcapStatus.BAD_REQUEST);
            return;
        }

        Encapsulated parsed = readEncapsulated(encapsulated, icapHeaders.contains("Preview"), in, out);

        boolean allow204 = headerListContains(icapHeaders, "Allow", "204");
        Verdict verdict = decideVerdict(parsed.body);

        if (verdict == Verdict.INFECTED) {
            writeBlockedResponse(method, out);
        } else if (allow204) {
            // Nothing to change and the client said it accepts 204 -> the cheapest "clean" answer.
            IcapHeaders h = new IcapHeaders();
            h.set("ISTag", quoted(istag));
            writeStatusLine(out, IcapStatus.NO_CONTENT);
            writeHeaders(out, h);
            out.write(CRLF);
        } else {
            // Client did not offer Allow: 204 -> echo the original message back unmodified as 200 OK.
            writeEchoResponse(method, parsed, out);
        }
    }

    // ---------------------------------------------------------------------
    // Encapsulated payload reading
    // ---------------------------------------------------------------------

    /** The decoded encapsulated message: the raw header block(s) and the assembled body. */
    private static final class Encapsulated {
        byte[] reqHdr = new byte[0];
        byte[] resHdr = new byte[0];
        byte[] body = new byte[0];
        boolean bodyPresent;
    }

    /**
     * Reads the encapsulated sections in the order declared by the {@code Encapsulated} header. Header
     * sections have a known length (next offset minus this offset); the body section is chunked and, when a
     * {@code Preview} was advertised, may be split by a {@code 100 Continue} handshake.
     */
    private Encapsulated readEncapsulated(String encapsulated, boolean preview,
                                          BufferedInputStream in, BufferedOutputStream out) throws IOException {
        List<Section> sections = parseEncapsulated(encapsulated);
        Encapsulated result = new Encapsulated();

        for (int i = 0; i < sections.size(); i++) {
            Section section = sections.get(i);
            switch (section.name) {
                case "req-hdr" -> result.reqHdr = readFully(in, sectionLength(sections, i));
                case "res-hdr" -> result.resHdr = readFully(in, sectionLength(sections, i));
                case "req-body", "res-body", "opt-body" -> {
                    result.bodyPresent = true;
                    result.body = readEncapsulatedBody(preview, in, out);
                }
                case "null-body" -> { /* no body to read */ }
                default -> { /* ignore unknown sections defensively */ }
            }
        }
        return result;
    }

    /**
     * Reads a (possibly previewed) chunked body. When a {@code Preview} was advertised and the preview did
     * not contain the whole body ({@code ieof}), it sends {@code 100 Continue} on {@code out} and reads the
     * remainder.
     */
    private byte[] readEncapsulatedBody(boolean preview, BufferedInputStream in, BufferedOutputStream out)
            throws IOException {
        ChunkRead first = readChunks(in);
        if (preview && !first.endedWithIeof) {
            writeStatusLine(out, IcapStatus.CONTINUE);
            out.write(CRLF); // 100 Continue has no headers, just a blank line
            out.flush();
            ChunkRead rest = readChunks(in);
            return concat(first.bytes, rest.bytes);
        }
        return first.bytes;
    }

    /** Holds the bytes read from a run of HTTP chunks plus whether the terminator carried {@code ieof}. */
    private static final class ChunkRead {
        final byte[] bytes;
        final boolean endedWithIeof;

        ChunkRead(byte[] bytes, boolean endedWithIeof) {
            this.bytes = bytes;
            this.endedWithIeof = endedWithIeof;
        }
    }

    /**
     * Reads HTTP chunked-transfer data up to and including the terminating zero-length chunk. Recognises the
     * ICAP {@code "0; ieof"} preview terminator, which signals that the preview already contained the whole
     * body (so no {@code 100 Continue} round-trip is required).
     */
    private ChunkRead readChunks(BufferedInputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null) {
                break; // connection closed mid-body
            }
            if (sizeLine.isEmpty()) {
                continue;
            }
            String[] sizeAndExt = sizeLine.split(";", 2);
            int size = Integer.parseInt(sizeAndExt[0].trim(), 16);
            if (size == 0) {
                boolean ieof = sizeAndExt.length > 1 && sizeAndExt[1].toLowerCase().contains("ieof");
                // Consume any trailer lines up to the blank line.
                String trailer;
                while ((trailer = readLine(in)) != null && !trailer.isEmpty()) {
                    // discard
                }
                return new ChunkRead(buffer.toByteArray(), ieof);
            }
            buffer.write(readFully(in, size));
            readLine(in); // consume the CRLF after the chunk data
        }
        return new ChunkRead(buffer.toByteArray(), false);
    }

    // ---------------------------------------------------------------------
    // Verdict + response writing
    // ---------------------------------------------------------------------

    /** The trivial policy outcomes this test server can return. */
    private enum Verdict { CLEAN, INFECTED }

    private Verdict decideVerdict(byte[] body) {
        // A forced-fail stand reports everything as infected; otherwise only the EICAR signature trips it.
        if (!checkPasses) {
            return Verdict.INFECTED;
        }
        return indexOf(body, EICAR_SIGNATURE) >= 0 ? Verdict.INFECTED : Verdict.CLEAN;
    }

    /** Writes a {@code 200 OK} whose encapsulated message is a "blocked" replacement page. */
    private void writeBlockedResponse(String method, BufferedOutputStream out) throws IOException {
        byte[] page = "Blocked by ICAP test server: EICAR test signature detected.\n"
                .getBytes(StandardCharsets.UTF_8);
        byte[] httpHdr = ("HTTP/1.1 403 Forbidden\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: " + page.length + "\r\n"
                + "\r\n").getBytes(StandardCharsets.ISO_8859_1);

        // REQMOD blocks become a req-hdr+req-body; RESPMOD becomes res-hdr+res-body.
        String hdrToken = method.equals("REQMOD") ? "req-hdr" : "res-hdr";
        String bodyToken = method.equals("REQMOD") ? "req-body" : "res-body";

        IcapHeaders headers = new IcapHeaders();
        headers.set("ISTag", quoted(istag));
        headers.set("X-Infection-Found", "Type=0; Resolution=2; Threat=EICAR-Test-File;");
        headers.set("X-Violations-Found", "1");
        headers.set("Encapsulated", hdrToken + "=0, " + bodyToken + "=" + httpHdr.length);

        writeStatusLine(out, IcapStatus.OK);
        writeHeaders(out, headers);
        out.write(CRLF);
        out.write(httpHdr);
        writeChunkedBody(out, page);
    }

    /** Writes a {@code 200 OK} that returns the original encapsulated message unchanged. */
    private void writeEchoResponse(String method, Encapsulated parsed, BufferedOutputStream out)
            throws IOException {
        IcapHeaders headers = new IcapHeaders();
        headers.set("ISTag", quoted(istag));

        StringBuilder enc = new StringBuilder();
        int offset = 0;
        if (parsed.reqHdr.length > 0) {
            enc.append("req-hdr=").append(offset);
            offset += parsed.reqHdr.length;
        }
        if (parsed.resHdr.length > 0) {
            if (enc.length() > 0) {
                enc.append(", ");
            }
            enc.append("res-hdr=").append(offset);
            offset += parsed.resHdr.length;
        }
        if (enc.length() > 0) {
            enc.append(", ");
        }
        if (parsed.bodyPresent) {
            enc.append(method.equals("REQMOD") ? "req-body=" : "res-body=").append(offset);
        } else {
            enc.append("null-body=").append(offset);
        }
        headers.set("Encapsulated", enc.toString());

        writeStatusLine(out, IcapStatus.OK);
        writeHeaders(out, headers);
        out.write(CRLF);
        out.write(parsed.reqHdr);
        out.write(parsed.resHdr);
        if (parsed.bodyPresent) {
            writeChunkedBody(out, parsed.body);
        }
    }

    /** Writes a bodyless status response (status line + ISTag + blank line). */
    private void writeSimpleResponse(BufferedOutputStream out, int status) throws IOException {
        IcapHeaders headers = new IcapHeaders();
        headers.set("ISTag", quoted(istag));
        headers.set("Encapsulated", "null-body=0");
        writeStatusLine(out, status);
        writeHeaders(out, headers);
        out.write(CRLF);
        out.flush();
    }

    // ---------------------------------------------------------------------
    // Low-level wire helpers (mirror DefaultIcapClient)
    // ---------------------------------------------------------------------

    private void writeStatusLine(OutputStream out, int code) throws IOException {
        writeAscii(out, ICAP_VERSION + " " + code + " " + IcapStatus.reasonPhrase(code));
        out.write(CRLF);
    }

    private void writeHeaders(OutputStream out, IcapHeaders headers) throws IOException {
        List<String[]> flat = new ArrayList<>();
        headers.forEach((n, v) -> flat.add(new String[]{n, v}));
        for (String[] h : flat) {
            writeAscii(out, h[0] + ": " + h[1]);
            out.write(CRLF);
        }
    }

    /** Writes the bytes as a single HTTP chunk followed by the zero-length terminator. */
    private void writeChunkedBody(OutputStream out, byte[] body) throws IOException {
        if (body.length > 0) {
            writeAscii(out, Integer.toHexString(body.length));
            out.write(CRLF);
            out.write(body);
            out.write(CRLF);
        }
        writeAscii(out, "0");
        out.write(CRLF);
        out.write(CRLF);
    }

    private void writeAscii(OutputStream out, String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    private IcapHeaders readHeaders(BufferedInputStream in) throws IOException {
        IcapHeaders headers = new IcapHeaders();
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            headers.add(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
        }
        return headers;
    }

    private List<Section> parseEncapsulated(String value) {
        List<Section> sections = new ArrayList<>();
        for (String part : value.split(",")) {
            String token = part.trim();
            if (token.isEmpty()) {
                continue;
            }
            int eq = token.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            sections.add(new Section(token.substring(0, eq).trim(),
                    Integer.parseInt(token.substring(eq + 1).trim())));
        }
        return sections;
    }

    private int sectionLength(List<Section> sections, int index) {
        Section current = sections.get(index);
        int next = (index + 1 < sections.size()) ? sections.get(index + 1).offset : current.offset;
        return Math.max(0, next - current.offset);
    }

    private byte[] readFully(InputStream in, int len) throws IOException {
        byte[] data = new byte[len];
        int read = 0;
        while (read < len) {
            int n = in.read(data, read, len - read);
            if (n < 0) {
                throw new IOException("unexpected EOF: wanted " + len + " bytes, got " + read);
            }
            read += n;
        }
        return data;
    }

    private String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int b;
        boolean any = false;
        while ((b = in.read()) != -1) {
            any = true;
            if (b == '\n') {
                break;
            }
            if (b == '\r') {
                continue;
            }
            buffer.write(b);
        }
        if (!any && buffer.size() == 0) {
            return null;
        }
        return buffer.toString(StandardCharsets.ISO_8859_1);
    }

    private static boolean headerListContains(IcapHeaders headers, String name, String token) {
        for (String v : headers.get(name)) {
            for (String part : v.split(",")) {
                if (part.trim().equalsIgnoreCase(token)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String quoted(String s) {
        return "\"" + s + "\"";
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || haystack.length < needle.length) {
            return -1;
        }
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private void log(String message) {
        System.out.println("[icap-test-server] " + message);
    }

    /** One {@code Encapsulated} entry: section name + byte offset. */
    private static final class Section {
        final String name;
        final int offset;

        Section(String name, int offset) {
            this.name = name;
            this.offset = offset;
        }
    }

    /**
     * Standalone entry point. Usage: {@code IcapTestServer [port]} (default 1344).
     */
    public static void main(String[] args) throws Exception {
        int port = (args.length > 0) ? Integer.parseInt(args[0]) : 1344;
        IcapTestServer server = new IcapTestServer(port);
        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
        server.start();
        // Block the main thread until the JVM is interrupted/killed.
        Thread.currentThread().join();
    }
}
