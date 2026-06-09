package ru.vtb.vkod.platform2.icapintegration.client;

import ru.vtb.vkod.platform2.icapintegration.exception.IcapConnectionException;
import ru.vtb.vkod.platform2.icapintegration.exception.IcapException;
import ru.vtb.vkod.platform2.icapintegration.exception.IcapProtocolException;
import ru.vtb.vkod.platform2.icapintegration.model.IcapRequest;
import ru.vtb.vkod.platform2.icapintegration.model.IcapResponse;

/**
 * High-level entry point for talking to an ICAP server (RFC 3507).
 *
 * <p>A single instance is thread-safe and may be injected and shared across the application. Each call
 * performs one ICAP exchange over a freshly opened TCP (or TLS) connection.</p>
 *
 * <p>Typical antivirus/content-scan usage:</p>
 * <pre>{@code
 * @Autowired IcapClient icap;
 *
 * IcapResponse resp = icap.scan(fileBytes, "upload.bin");
 * if (resp.isBlockedOrInfected()) {
 *     throw new SecurityException("Rejected: " + resp.getInfectionFound().orElse("policy violation"));
 * }
 * }</pre>
 *
 * <p>All methods translate transport failures into {@link IcapConnectionException} and malformed replies
 * into {@link IcapProtocolException}; both extend {@link IcapException}.</p>
 */
public interface IcapClient {

    /**
     * Sends an {@code OPTIONS} request to discover a service's capabilities (supported methods, preview
     * size, {@code ISTag}, {@code Allow}, TTL, ...).
     *
     * @param service the service path/name, or {@code null} to use the configured default service
     * @return the parsed options response (inspect its headers, e.g. {@code Methods}, {@code Preview})
     * @throws IcapException on transport or protocol failure
     */
    IcapResponse options(String service);

    /**
     * Sends a {@code REQMOD} (request modification) exchange.
     *
     * @param request the request carrying the encapsulated HTTP request (and optional body)
     * @return the parsed ICAP response
     * @throws IcapException on transport or protocol failure
     */
    IcapResponse reqmod(IcapRequest request);

    /**
     * Sends a {@code RESPMOD} (response modification) exchange.
     *
     * @param request the request carrying the encapsulated HTTP response headers and body
     * @return the parsed ICAP response
     * @throws IcapException on transport or protocol failure
     */
    IcapResponse respmod(IcapRequest request);

    /**
     * Convenience helper that scans raw content via {@code RESPMOD} against the default service. It
     * synthesizes a minimal encapsulated HTTP request/response around the bytes so that the most common
     * "scan this payload for malware" use case is a one-liner.
     *
     * @param content  the bytes to scan
     * @param filename a logical filename used in the synthesized HTTP request line (for server logging);
     *                 may be {@code null}
     * @return the parsed ICAP response (use {@link IcapResponse#isBlockedOrInfected()} for a quick verdict)
     * @throws IcapException on transport or protocol failure
     */
    IcapResponse scan(byte[] content, String filename);
}
