package io.github.icap.spring.boot.exception;

/**
 * Thrown when the server's reply cannot be parsed as a valid ICAP message: a malformed status line,
 * an unparseable {@code Encapsulated} header, a truncated body, etc. Indicates the bytes on the wire
 * did not conform to RFC 3507 (as opposed to a transport failure, which is an
 * {@link IcapConnectionException}).
 */
public class IcapProtocolException extends IcapException {

    public IcapProtocolException(String message) {
        super(message);
    }

    public IcapProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}
