package ru.vtb.vkod.platform2.icapintegration.exception;

/**
 * Thrown when the client cannot establish or maintain the TCP connection to the ICAP server, or when an
 * I/O error occurs while reading/writing the socket (connect timeout, read timeout, connection reset, ...).
 */
public class IcapConnectionException extends IcapException {

    public IcapConnectionException(String message, Throwable cause) {
        super(message, cause);
    }

    public IcapConnectionException(String message) {
        super(message);
    }
}
