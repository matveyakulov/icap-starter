package io.github.icap.spring.boot.model;

/**
 * ICAP status codes and their reason phrases (RFC 3507, section 4.3.3, which largely
 * mirrors the HTTP/1.1 status registry but adds a few ICAP-specific codes).
 *
 * <p>This is a small helper holder of {@code int} constants rather than an {@code enum}
 * so that unknown/extension status codes returned by a server are still representable
 * without forcing a mapping.</p>
 */
public final class IcapStatus {

    private IcapStatus() {
        // utility holder; not instantiable
    }

    // ----- 1xx informational -----
    /** Interim response sent after a {@code Preview} to ask the client to send the rest of the body. */
    public static final int CONTINUE = 100;

    // ----- 2xx success -----
    /** The encapsulated message was processed; an adapted message is returned. */
    public static final int OK = 200;
    /**
     * "No modifications needed" &mdash; the server inspected the content and is happy with it
     * as-is. Only returned when the client offered {@code Allow: 204}. For an antivirus
     * service this typically means "clean / not blocked".
     */
    public static final int NO_CONTENT = 204;

    // ----- 4xx client errors -----
    /** Malformed ICAP request. */
    public static final int BAD_REQUEST = 400;
    /** The referenced ICAP service does not exist on the server. */
    public static final int SERVICE_NOT_FOUND = 404;
    /** The method is not allowed for the referenced service (e.g. REQMOD on a RESPMOD-only service). */
    public static final int METHOD_NOT_ALLOWED = 405;
    /** Request timed out. */
    public static final int REQUEST_TIMEOUT = 408;

    // ----- 5xx server errors -----
    /** Generic server error. */
    public static final int SERVER_ERROR = 500;
    /** Method not implemented by the server. */
    public static final int NOT_IMPLEMENTED = 501;
    /** Bad gateway (the ICAP server acting as a gateway got an invalid upstream response). */
    public static final int BAD_GATEWAY = 502;
    /** Service temporarily overloaded; the client may retry later. */
    public static final int SERVICE_OVERLOADED = 503;
    /** The server does not support the requested ICAP version. */
    public static final int ICAP_VERSION_NOT_SUPPORTED = 505;

    /**
     * Returns a best-effort, human-readable reason phrase for a status code. Used purely for
     * logging/diagnostics; the authoritative reason phrase is whatever the server sent on the
     * status line.
     *
     * @param code the ICAP status code
     * @return the canonical reason phrase, or {@code "Unknown"} for unrecognised codes
     */
    public static String reasonPhrase(int code) {
        return switch (code) {
            case CONTINUE -> "Continue";
            case OK -> "OK";
            case NO_CONTENT -> "No Content";
            case BAD_REQUEST -> "Bad Request";
            case SERVICE_NOT_FOUND -> "ICAP Service Not Found";
            case METHOD_NOT_ALLOWED -> "Method Not Allowed";
            case REQUEST_TIMEOUT -> "Request Timeout";
            case SERVER_ERROR -> "Server Error";
            case NOT_IMPLEMENTED -> "Method Not Implemented";
            case BAD_GATEWAY -> "Bad Gateway";
            case SERVICE_OVERLOADED -> "Service Overloaded";
            case ICAP_VERSION_NOT_SUPPORTED -> "ICAP Version Not Supported";
            default -> "Unknown";
        };
    }
}
