package ru.vtb.vkod.platform2.icapintegration.exception;

/**
 * Base unchecked exception for all ICAP client failures.
 *
 * <p>It is unchecked so that callers are not forced to wrap every {@code scan(...)} call in a
 * {@code try/catch}, while still allowing targeted handling of {@link IcapConnectionException} and
 * {@link IcapProtocolException} subtypes when desired.</p>
 */
public class IcapException extends RuntimeException {

    public IcapException(String message) {
        super(message);
    }

    public IcapException(String message, Throwable cause) {
        super(message, cause);
    }
}
