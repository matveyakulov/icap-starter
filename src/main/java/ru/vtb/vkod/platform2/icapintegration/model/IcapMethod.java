package ru.vtb.vkod.platform2.icapintegration.model;

/**
 * The three request methods defined by the ICAP protocol (RFC 3507, section 4).
 *
 * <ul>
 *     <li>{@link #OPTIONS} &mdash; discover the capabilities of an ICAP service
 *         (supported methods, preview size, {@code ISTag}, {@code Allow}, TTL, ...).</li>
 *     <li>{@link #REQMOD} &mdash; <em>Request Modification</em>: the client encapsulates
 *         an HTTP <strong>request</strong> for the ICAP server to inspect/adapt before it is
 *         forwarded to an origin server.</li>
 *     <li>{@link #RESPMOD} &mdash; <em>Response Modification</em>: the client encapsulates an
 *         HTTP <strong>response</strong> (headers and/or body) for the ICAP server to
 *         inspect/adapt. This is the method used for the common "scan this content" use case
 *         (antivirus, DLP, content filtering).</li>
 * </ul>
 */
public enum IcapMethod {

    /** Capability discovery. Carries no encapsulated HTTP message body. */
    OPTIONS,

    /** Request modification &mdash; encapsulates an HTTP request. */
    REQMOD,

    /** Response modification &mdash; encapsulates an HTTP response. */
    RESPMOD
}
