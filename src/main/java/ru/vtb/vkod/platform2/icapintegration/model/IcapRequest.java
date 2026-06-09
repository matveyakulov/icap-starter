package ru.vtb.vkod.platform2.icapintegration.model;

import lombok.Getter;

import java.nio.charset.StandardCharsets;

/**
 * An immutable ICAP request to be sent by an {@link ru.vtb.vkod.platform2.icapintegration.client.IcapClient}.
 *
 * <p>An ICAP message ({@code REQMOD}/{@code RESPMOD}) <em>encapsulates</em> an HTTP message. This
 * class models the three encapsulated parts plus the ICAP method/service:</p>
 * <ul>
 *     <li><b>HTTP request header</b> ({@code req-hdr}) &mdash; the request line + headers of the
 *         encapsulated HTTP request. Required for {@code REQMOD}; optional context for {@code RESPMOD}.</li>
 *     <li><b>HTTP response header</b> ({@code res-hdr}) &mdash; the status line + headers of the
 *         encapsulated HTTP response. Used for {@code RESPMOD}.</li>
 *     <li><b>Body</b> &mdash; the encapsulated entity body (the bytes being scanned/adapted). When
 *         empty the request advertises {@code null-body}.</li>
 * </ul>
 *
 * <p>The header blocks are supplied as Strings; per RFC 3507 they are transmitted verbatim using the
 * ISO-8859-1 (Latin-1) charset and each block must be terminated by a blank line ({@code CRLF CRLF}).
 * The {@link Builder} does <em>not</em> rewrite or validate the HTTP headers &mdash; you are responsible
 * for providing well-formed HTTP header blocks (the {@code scan} helpers on the client build sensible
 * defaults for you).</p>
 *
 * <p>Instances are created via {@link #builder(IcapMethod)} and are safe to reuse/share.</p>
 */
@Getter
public final class IcapRequest {

    /** The ICAP method. */
    private final IcapMethod method;
    /**
     * The service path/name on the ICAP server (e.g. {@code "avscan"}), or {@code null} to fall back to
     * the client's configured default service.
     */
    private final String service;
    /** The encapsulated HTTP request header block, or {@code null} if not present. */
    private final String httpRequestHeader;
    /** The encapsulated HTTP response header block, or {@code null} if not present. */
    private final String httpResponseHeader;
    /** The encapsulated entity body bytes (never {@code null}; may be empty). */
    private final byte[] body;
    /** Additional ICAP-level headers to send (never {@code null}). */
    private final IcapHeaders headers;

    private IcapRequest(Builder b) {
        this.method = b.method;
        this.service = b.service;
        this.httpRequestHeader = b.httpRequestHeader;
        this.httpResponseHeader = b.httpResponseHeader;
        this.body = b.body;
        this.headers = b.headers;
    }

    /**
     * Starts building a request for the given method.
     *
     * @param method the ICAP method
     * @return a new {@link Builder}
     */
    public static Builder builder(IcapMethod method) {
        return new Builder(method);
    }

    /** @return {@code true} if there is a non-empty encapsulated body. */
    public boolean hasBody() {
        return body.length > 0;
    }

    /**
     * Fluent builder for {@link IcapRequest}.
     */
    public static final class Builder {
        private final IcapMethod method;
        private String service;
        private String httpRequestHeader;
        private String httpResponseHeader;
        private byte[] body = new byte[0];
        private final IcapHeaders headers = new IcapHeaders();

        private Builder(IcapMethod method) {
            if (method == null) {
                throw new IllegalArgumentException("method must not be null");
            }
            this.method = method;
        }

        /**
         * Overrides the ICAP service to target for this request (otherwise the client default is used).
         *
         * @param service service path/name, without a leading slash (e.g. {@code "avscan"})
         * @return this builder
         */
        public Builder service(String service) {
            this.service = service;
            return this;
        }

        /**
         * Sets the encapsulated HTTP request header block (request line + headers, ending in a blank line).
         *
         * @param httpRequestHeader the raw HTTP request header block
         * @return this builder
         */
        public Builder httpRequestHeader(String httpRequestHeader) {
            this.httpRequestHeader = httpRequestHeader;
            return this;
        }

        /**
         * Sets the encapsulated HTTP response header block (status line + headers, ending in a blank line).
         *
         * @param httpResponseHeader the raw HTTP response header block
         * @return this builder
         */
        public Builder httpResponseHeader(String httpResponseHeader) {
            this.httpResponseHeader = httpResponseHeader;
            return this;
        }

        /**
         * Sets the encapsulated entity body.
         *
         * @param body the body bytes; {@code null} is treated as empty
         * @return this builder
         */
        public Builder body(byte[] body) {
            this.body = (body == null) ? new byte[0] : body;
            return this;
        }

        /**
         * Convenience overload that encodes the supplied text as UTF-8.
         *
         * @param body the body text
         * @return this builder
         */
        public Builder body(String body) {
            return body(body == null ? null : body.getBytes(StandardCharsets.UTF_8));
        }

        /**
         * Adds an extra ICAP-level request header (e.g. {@code X-Client-IP}).
         *
         * @param name  header name
         * @param value header value
         * @return this builder
         */
        public Builder header(String name, String value) {
            this.headers.add(name, value);
            return this;
        }

        /** @return the immutable {@link IcapRequest}. */
        public IcapRequest build() {
            return new IcapRequest(this);
        }
    }
}
