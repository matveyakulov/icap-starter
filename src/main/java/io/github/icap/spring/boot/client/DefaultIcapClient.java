package io.github.icap.spring.boot.client;

import io.github.icap.spring.boot.exception.IcapConnectionException;
import io.github.icap.spring.boot.exception.IcapProtocolException;
import io.github.icap.spring.boot.model.IcapHeaders;
import io.github.icap.spring.boot.model.IcapMethod;
import io.github.icap.spring.boot.model.IcapRequest;
import io.github.icap.spring.boot.model.IcapResponse;
import io.github.icap.spring.boot.model.IcapStatus;

import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Default, dependency-free {@link IcapClient} that speaks ICAP/1.0 (RFC 3507) directly over a TCP socket
 * (or TLS socket when enabled). One short-lived connection is opened per exchange and closed afterwards,
 * which keeps the implementation simple and robust; servers that prefer keep-alive will simply see a new
 * connection each time.
 *
 * <h2>Wire format produced for a request</h2>
 * <pre>{@code
 * RESPMOD icap://host:port/service ICAP/1.0\r\n
 * Host: host\r\n
 * Allow: 204\r\n                         (optional - lets the server answer "no modifications needed")
 * Preview: 4096\r\n                      (optional - send a preview before the full body)
 * Encapsulated: req-hdr=0, res-hdr=NN, res-body=MM\r\n
 * \r\n
 * <req-hdr block bytes><res-hdr block bytes><body as HTTP chunked transfer-encoding>
 * }</pre>
 *
 * <p>The {@code Encapsulated} header is mandatory and lists each encapsulated section together with its
 * byte offset (relative to the start of the encapsulated payload). Header sections are sent verbatim; the
 * body section is sent using HTTP chunked encoding and terminated by a zero-length chunk.</p>
 *
 * <h2>Preview / 100 Continue</h2>
 * <p>When preview is enabled the client sends only the first <em>N</em> bytes of the body, then waits. The
 * server may answer immediately with a final status (e.g. {@code 204}/{@code 200}) based on the preview, or
 * reply {@code 100 Continue} to request the remainder, which the client then streams.</p>
 *
 * <p>This class is immutable and therefore thread-safe.</p>
 */
public class DefaultIcapClient implements IcapClient {

    /** ICAP and the encapsulated HTTP headers are 8-bit clean Latin-1 per the HTTP spec. */
    private static final byte[] CRLF = {'\r', '\n'};
    private static final String ICAP_VERSION = "ICAP/1.0";

    private final String host;
    private final int port;
    private final String defaultService;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final boolean previewEnabled;
    private final int previewSize;
    private final boolean allow204;
    private final boolean tls;

    /**
     * Creates a configured client.
     *
     * @param host             ICAP server host
     * @param port             ICAP server port (default ICAP port is 1344)
     * @param defaultService   service path/name used when a request does not specify one
     * @param connectTimeoutMs TCP connect timeout in milliseconds (0 = infinite)
     * @param readTimeoutMs    socket read timeout in milliseconds (0 = infinite)
     * @param previewEnabled   whether to use the ICAP {@code Preview} mechanism
     * @param previewSize      number of body bytes to send as a preview
     * @param allow204         whether to advertise {@code Allow: 204} (let the server skip returning a body)
     * @param tls              whether to connect using TLS (ICAPS)
     */
    public DefaultIcapClient(String host, int port, String defaultService,
                             int connectTimeoutMs, int readTimeoutMs,
                             boolean previewEnabled, int previewSize,
                             boolean allow204, boolean tls) {
        this.host = host;
        this.port = port;
        this.defaultService = defaultService;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.previewEnabled = previewEnabled;
        this.previewSize = previewSize;
        this.allow204 = allow204;
        this.tls = tls;
    }

    // ---------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------

    @Override
    public IcapResponse options(String service) {
        return execute(IcapRequest.builder(IcapMethod.OPTIONS).service(service).build());
    }

    @Override
    public IcapResponse reqmod(IcapRequest request) {
        require(request.getMethod() == IcapMethod.REQMOD, "reqmod() requires an REQMOD request");
        return execute(request);
    }

    @Override
    public IcapResponse respmod(IcapRequest request) {
        require(request.getMethod() == IcapMethod.RESPMOD, "respmod() requires a RESPMOD request");
        return execute(request);
    }

    @Override
    public IcapResponse scan(byte[] content, String filename) {
        byte[] payload = (content == null) ? new byte[0] : content;
        String resource = (filename == null || filename.isBlank()) ? "/" : "/" + filename;

        // Synthesize a minimal, well-formed encapsulated HTTP request + response around the payload.
        // Many ICAP AV services want both an HTTP request header (what was requested) and an HTTP
        // response header (what is being returned) for RESPMOD.
        String reqHdr = "GET " + resource + " HTTP/1.1\r\n"
                + "Host: " + host + "\r\n"
                + "\r\n";
        String resHdr = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: application/octet-stream\r\n"
                + "Content-Length: " + payload.length + "\r\n"
                + "\r\n";

        IcapRequest request = IcapRequest.builder(IcapMethod.RESPMOD)
                .httpRequestHeader(reqHdr)
                .httpResponseHeader(resHdr)
                .body(payload)
                .build();
        return execute(request);
    }

    // ---------------------------------------------------------------------
    // Exchange orchestration
    // ---------------------------------------------------------------------

    /**
     * Opens a connection, writes the request, reads the reply and returns the parsed response.
     */
    private IcapResponse execute(IcapRequest request) {
        String service = (request.getService() != null) ? request.getService() : defaultService;

        Socket socket = null;
        try {
            socket = openSocket();
            OutputStream rawOut = socket.getOutputStream();
            InputStream rawIn = socket.getInputStream();
            BufferedOutputStream out = new BufferedOutputStream(rawOut);
            BufferedInputStream in = new BufferedInputStream(rawIn);

            return sendAndReceive(request, service, out, in);
        } catch (IOException e) {
            throw new IcapConnectionException(
                    "I/O error during ICAP exchange with " + host + ":" + port, e);
        } finally {
            closeQuietly(socket);
        }
    }

    private Socket openSocket() throws IOException {
        Socket socket = tls ? SSLSocketFactory.getDefault().createSocket() : new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);
            return socket;
        } catch (IOException e) {
            closeQuietly(socket);
            throw new IcapConnectionException(
                    "Unable to connect to ICAP server " + host + ":" + port, e);
        }
    }

    private IcapResponse sendAndReceive(IcapRequest request, String service,
                                        BufferedOutputStream out, BufferedInputStream in) throws IOException {

        byte[] reqHdr = bytesOrEmpty(request.getHttpRequestHeader());
        byte[] resHdr = bytesOrEmpty(request.getHttpResponseHeader());
        byte[] body = request.getBody();
        boolean hasBody = request.hasBody();

        // Decide whether to use Preview for this exchange: only meaningful when a body is present.
        boolean usePreview = previewEnabled && hasBody && request.getMethod() != IcapMethod.OPTIONS;
        int previewLen = usePreview ? Math.min(previewSize, body.length) : 0;

        // ---- 1. ICAP request line + headers ----
        writeAscii(out, request.getMethod().name() + " " + buildUri(service) + " " + ICAP_VERSION);
        out.write(CRLF);
        writeHeader(out, "Host", host);
        if (allow204) {
            // Tell the server it may answer "204 No Content" when nothing needs changing.
            writeHeader(out, "Allow", "204");
        }
        if (usePreview) {
            writeHeader(out, "Preview", Integer.toString(previewLen));
        }
        // Caller-supplied extra ICAP headers. Collect first (no IO in the lambda), then write.
        List<String[]> extraHeaders = new ArrayList<>();
        request.getHeaders().forEach((n, v) -> extraHeaders.add(new String[]{n, v}));
        for (String[] h : extraHeaders) {
            writeHeader(out, h[0], h[1]);
        }
        writeHeader(out, "Encapsulated", buildEncapsulated(request.getMethod(), reqHdr, resHdr, hasBody));
        out.write(CRLF); // blank line terminates the ICAP header block

        // ---- 2. Encapsulated header sections (sent verbatim, not chunked) ----
        out.write(reqHdr);
        out.write(resHdr);

        // ---- 3. Encapsulated body ----
        if (!hasBody) {
            out.flush();
            return readResponse(in, null);
        }

        if (usePreview) {
            // Send the preview portion as one or more chunks, then signal end-of-preview.
            writeChunk(out, body, 0, previewLen);
            boolean previewIsWholeBody = (previewLen == body.length);
            if (previewIsWholeBody) {
                // "ieof" extension means: this preview already contains the entire body.
                writeAscii(out, "0; ieof");
                out.write(CRLF);
                out.write(CRLF);
            } else {
                writeLastChunk(out);
            }
            out.flush();

            // Read the interim/final response to the preview.
            ParsedHead head = readHead(in);
            if (head.statusCode == IcapStatus.CONTINUE) {
                // Server wants the rest of the body.
                writeChunk(out, body, previewLen, body.length - previewLen);
                writeLastChunk(out);
                out.flush();
                return readResponse(in, null);
            }
            // Server reached a verdict from the preview alone (e.g. 204/200): finish reading that response.
            return readResponse(in, head);
        }

        // No preview: stream the whole body, then read the response.
        writeChunk(out, body, 0, body.length);
        writeLastChunk(out);
        out.flush();
        return readResponse(in, null);
    }

    // ---------------------------------------------------------------------
    // Request serialization helpers
    // ---------------------------------------------------------------------

    private String buildUri(String service) {
        String svc = (service == null) ? "" : service;
        if (svc.startsWith("/")) {
            svc = svc.substring(1);
        }
        return "icap://" + host + ":" + port + "/" + svc;
    }

    /**
     * Builds the mandatory {@code Encapsulated} header value, listing each present section and its byte
     * offset within the encapsulated payload. Section order is fixed by RFC 3507:
     * {@code req-hdr}, {@code res-hdr}, then exactly one of {@code req-body}/{@code res-body}/{@code null-body}.
     */
    private String buildEncapsulated(IcapMethod method, byte[] reqHdr, byte[] resHdr, boolean hasBody) {
        StringBuilder sb = new StringBuilder();
        int offset = 0;

        if (reqHdr.length > 0) {
            sb.append("req-hdr=").append(offset);
            offset += reqHdr.length;
        }
        if (resHdr.length > 0) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("res-hdr=").append(offset);
            offset += resHdr.length;
        }
        if (sb.length() > 0) {
            sb.append(", ");
        }
        if (hasBody) {
            String bodyToken = (method == IcapMethod.REQMOD) ? "req-body" : "res-body";
            sb.append(bodyToken).append('=').append(offset);
        } else {
            // OPTIONS and bodyless REQMOD/RESPMOD must still declare a null-body section.
            sb.append("null-body=").append(offset);
        }
        return sb.toString();
    }

    /** Writes one HTTP chunked-transfer chunk: {@code <hex-length>CRLF<data>CRLF}. */
    private void writeChunk(OutputStream out, byte[] data, int off, int len) throws IOException {
        if (len <= 0) {
            return;
        }
        writeAscii(out, Integer.toHexString(len));
        out.write(CRLF);
        out.write(data, off, len);
        out.write(CRLF);
    }

    /** Writes the terminating zero-length chunk ({@code 0CRLFCRLF}). */
    private void writeLastChunk(OutputStream out) throws IOException {
        writeAscii(out, "0");
        out.write(CRLF);
        out.write(CRLF);
    }

    private void writeHeader(OutputStream out, String name, String value) throws IOException {
        writeAscii(out, name + ": " + value);
        out.write(CRLF);
    }

    private void writeAscii(OutputStream out, String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    // ---------------------------------------------------------------------
    // Response parsing
    // ---------------------------------------------------------------------

    /**
     * Reads a full ICAP response. If {@code preParsedHead} is non-null the status line and headers have
     * already been consumed (used when a preview produced the final response directly); otherwise they are
     * read first. The encapsulated body, if any, is then read according to the {@code Encapsulated} header.
     */
    private IcapResponse readResponse(BufferedInputStream in, ParsedHead preParsedHead) throws IOException {
        ParsedHead head = (preParsedHead != null) ? preParsedHead : readHead(in);

        byte[] encapsulatedHeader = null;
        byte[] encapsulatedBody = null;

        String encapsulated = head.headers.getFirst("Encapsulated");
        if (encapsulated != null) {
            List<Section> sections = parseEncapsulated(encapsulated);
            for (int i = 0; i < sections.size(); i++) {
                Section section = sections.get(i);
                if (section.name.endsWith("-hdr")) {
                    // Header section length = next section offset - this offset.
                    int next = (i + 1 < sections.size()) ? sections.get(i + 1).offset : section.offset;
                    int len = Math.max(0, next - section.offset);
                    encapsulatedHeader = append(encapsulatedHeader, readFully(in, len));
                } else if (section.name.equals("res-body") || section.name.equals("req-body")) {
                    // The body is chunked; its length is not derivable from offsets.
                    encapsulatedBody = readChunkedBody(in);
                }
                // "null-body" => nothing to read.
            }
        }

        return new IcapResponse(head.statusCode, head.reasonPhrase, head.headers,
                encapsulatedHeader, encapsulatedBody);
    }

    /** Reads the ICAP status line and header block. */
    private ParsedHead readHead(BufferedInputStream in) throws IOException {
        String statusLine = readLine(in);
        if (statusLine == null) {
            throw new IcapConnectionException("ICAP server closed the connection before sending a response");
        }
        // Expected form: "ICAP/1.0 <code> <reason phrase>"
        if (!statusLine.startsWith("ICAP/")) {
            throw new IcapProtocolException("Malformed ICAP status line: '" + statusLine + "'");
        }
        int firstSpace = statusLine.indexOf(' ');
        int secondSpace = statusLine.indexOf(' ', firstSpace + 1);
        if (firstSpace < 0) {
            throw new IcapProtocolException("Malformed ICAP status line: '" + statusLine + "'");
        }
        String codeStr = (secondSpace < 0)
                ? statusLine.substring(firstSpace + 1)
                : statusLine.substring(firstSpace + 1, secondSpace);
        int code;
        try {
            code = Integer.parseInt(codeStr.trim());
        } catch (NumberFormatException e) {
            throw new IcapProtocolException("Unparseable ICAP status code in '" + statusLine + "'", e);
        }
        String reason = (secondSpace < 0) ? IcapStatus.reasonPhrase(code) : statusLine.substring(secondSpace + 1).trim();

        IcapHeaders headers = new IcapHeaders();
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue; // skip malformed header line defensively
            }
            headers.add(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
        }
        return new ParsedHead(code, reason, headers);
    }

    /** Parses an {@code Encapsulated} header value into an ordered list of (name, offset) sections. */
    private List<Section> parseEncapsulated(String value) {
        List<Section> sections = new ArrayList<>();
        for (String part : value.split(",")) {
            String token = part.trim();
            if (token.isEmpty()) {
                continue;
            }
            int eq = token.indexOf('=');
            if (eq <= 0) {
                throw new IcapProtocolException("Malformed Encapsulated entry: '" + token + "'");
            }
            String name = token.substring(0, eq).trim();
            int offset;
            try {
                offset = Integer.parseInt(token.substring(eq + 1).trim());
            } catch (NumberFormatException e) {
                throw new IcapProtocolException("Malformed Encapsulated offset: '" + token + "'", e);
            }
            sections.add(new Section(name, offset));
        }
        return sections;
    }

    /** Decodes an HTTP chunked-transfer body, returning the assembled bytes. */
    private byte[] readChunkedBody(BufferedInputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null) {
                break; // connection closed
            }
            if (sizeLine.isEmpty()) {
                continue;
            }
            // A chunk-size line may carry extensions after ';' (e.g. "0; ieof"); only the size matters.
            String hex = sizeLine.split(";", 2)[0].trim();
            int size;
            try {
                size = Integer.parseInt(hex, 16);
            } catch (NumberFormatException e) {
                throw new IcapProtocolException("Malformed chunk size: '" + sizeLine + "'", e);
            }
            if (size == 0) {
                // Last chunk: consume any trailer headers up to the terminating blank line.
                String trailer;
                while ((trailer = readLine(in)) != null && !trailer.isEmpty()) {
                    // discard trailers
                }
                break;
            }
            buffer.write(readFully(in, size));
            readLine(in); // consume the CRLF that terminates the chunk data
        }
        return buffer.toByteArray();
    }

    /**
     * Reads exactly {@code len} bytes, blocking as needed.
     *
     * @throws IcapConnectionException if EOF is reached before {@code len} bytes are read
     */
    private byte[] readFully(InputStream in, int len) throws IOException {
        byte[] data = new byte[len];
        int read = 0;
        while (read < len) {
            int n = in.read(data, read, len - read);
            if (n < 0) {
                throw new IcapConnectionException(
                        "Unexpected end of stream: expected " + len + " bytes, got " + read);
            }
            read += n;
        }
        return data;
    }

    /**
     * Reads a single CRLF-terminated line. Bare CR characters are ignored, and a lone LF terminates the
     * line. Returns {@code null} at end-of-stream when nothing was read. Lines are decoded as Latin-1.
     */
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

    // ---------------------------------------------------------------------
    // Misc helpers
    // ---------------------------------------------------------------------

    private static byte[] bytesOrEmpty(String s) {
        return (s == null) ? new byte[0] : s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] append(byte[] existing, byte[] more) {
        if (existing == null) {
            return more;
        }
        byte[] combined = new byte[existing.length + more.length];
        System.arraycopy(existing, 0, combined, 0, existing.length);
        System.arraycopy(more, 0, combined, existing.length, more.length);
        return combined;
    }

    private static void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // best-effort close
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    /** Holds a parsed status line + ICAP headers. */
    private static final class ParsedHead {
        final int statusCode;
        final String reasonPhrase;
        final IcapHeaders headers;

        ParsedHead(int statusCode, String reasonPhrase, IcapHeaders headers) {
            this.statusCode = statusCode;
            this.reasonPhrase = reasonPhrase;
            this.headers = headers;
        }
    }

    /** One entry of the {@code Encapsulated} header: a section name and its byte offset. */
    private static final class Section {
        final String name;
        final int offset;

        Section(String name, int offset) {
            this.name = name;
            this.offset = offset;
        }
    }
}
