package io.github.icap.spring.boot.model;

import lombok.Getter;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * The result of an ICAP exchange, as parsed from the server's reply.
 *
 * <p>Besides the ICAP status line and headers, the response may carry an <em>encapsulated</em> HTTP
 * message (the adapted request/response). For a {@code RESPMOD} virus-scan, the interesting outcomes are:</p>
 * <ul>
 *     <li>{@link IcapStatus#NO_CONTENT 204 No Content} &mdash; the server made no modifications; for an
 *         antivirus service this means the content is <em>clean / allowed</em>. See {@link #isNoModificationsNeeded()}.</li>
 *     <li>{@link IcapStatus#OK 200 OK} &mdash; the server returns an adapted message. For antivirus this
 *         usually means the content was <em>blocked/cleaned</em> and the body is a replacement (e.g. a block
 *         page). Inspect {@link #getInfectionFound()} and the encapsulated {@link #getEncapsulatedBody() body}.</li>
 * </ul>
 *
 * <p>Common diagnostic headers exposed via helpers: {@code ISTag} (service tag), {@code X-Infection-Found}
 * and {@code X-Violations-Found} (sent by many AV/DLP servers when a threat is detected).</p>
 */
@Getter
public final class IcapResponse {

    /** The numeric ICAP status code (e.g. 200, 204, 500). */
    private final int statusCode;
    /** The reason phrase from the ICAP status line. */
    private final String reasonPhrase;
    /** The ICAP response headers (never {@code null}). */
    private final IcapHeaders headers;
    /** The raw encapsulated HTTP header block returned by the server, or {@code null} if none. */
    private final byte[] encapsulatedHeader;
    /** The raw encapsulated (adapted) body returned by the server, or {@code null} if none. */
    private final byte[] encapsulatedBody;

    /**
     * Creates a response value object. Normally constructed by the client, but public to ease testing.
     *
     * @param statusCode         the ICAP status code
     * @param reasonPhrase       the reason phrase from the status line
     * @param headers            the ICAP response headers (never {@code null})
     * @param encapsulatedHeader the raw encapsulated HTTP header block returned by the server, or {@code null}
     * @param encapsulatedBody   the raw encapsulated (adapted) body returned by the server, or {@code null}
     */
    public IcapResponse(int statusCode, String reasonPhrase, IcapHeaders headers,
                        byte[] encapsulatedHeader, byte[] encapsulatedBody) {
        this.statusCode = statusCode;
        this.reasonPhrase = reasonPhrase;
        this.headers = (headers == null) ? new IcapHeaders() : headers;
        this.encapsulatedHeader = encapsulatedHeader;
        this.encapsulatedBody = encapsulatedBody;
    }

    // ---------------------------------------------------------------------
    // Convenience interpreters
    // ---------------------------------------------------------------------

    /** @return {@code true} for a 2xx status. */
    public boolean isSuccess() {
        return statusCode >= 200 && statusCode < 300;
    }

    /**
     * @return {@code true} if the server returned {@code 204 No Content}, i.e. the content needs no
     *         modification. For an antivirus service this is the "clean / allowed" signal.
     */
    public boolean isNoModificationsNeeded() {
        return statusCode == IcapStatus.NO_CONTENT;
    }

    /**
     * @return {@code true} if the server returned an adapted message ({@code 200 OK}). For an antivirus
     *         service this typically means the original content was blocked or replaced.
     */
    public boolean isModified() {
        return statusCode == IcapStatus.OK;
    }

    /** @return the value of the {@code ISTag} header (service/state tag), if present. */
    public Optional<String> getIstag() {
        return Optional.ofNullable(headers.getFirst("ISTag"));
    }

    /**
     * @return the value of the {@code X-Infection-Found} header sent by many antivirus ICAP services when
     *         malware is detected, if present. The format is server-specific, e.g.
     *         {@code "Type=0; Resolution=2; Threat=EICAR-Test-File;"}.
     */
    public Optional<String> getInfectionFound() {
        return Optional.ofNullable(headers.getFirst("X-Infection-Found"));
    }

    /** @return the value of the {@code X-Violations-Found} header (DLP/AV policy violations), if present. */
    public Optional<String> getViolationsFound() {
        return Optional.ofNullable(headers.getFirst("X-Violations-Found"));
    }

    /**
     * A best-effort verdict for the common antivirus/content-filter use case.
     *
     * <p>Returns {@code true} when the server signalled a threat/violation header, or when it returned an
     * adapted {@code 200 OK} (which conventionally means the original content was rejected and replaced).
     * A {@code 204 No Content} response is considered clean. This is a heuristic &mdash; always also consult
     * your specific ICAP server's documentation.</p>
     *
     * @return {@code true} if the content appears to have been flagged/blocked
     */
    public boolean isBlockedOrInfected() {
        if (getInfectionFound().isPresent() || getViolationsFound().isPresent()) {
            return true;
        }
        return isModified();
    }

    /**
     * Decodes the encapsulated header block as an ISO-8859-1 string for inspection.
     *
     * @return the encapsulated HTTP header block as text, or {@code null} if none
     */
    public String getEncapsulatedHeaderAsString() {
        return encapsulatedHeader == null ? null : new String(encapsulatedHeader, StandardCharsets.ISO_8859_1);
    }

    @Override
    public String toString() {
        return "IcapResponse{status=" + statusCode + " " + reasonPhrase
                + ", istag=" + getIstag().orElse("-")
                + ", bodyBytes=" + (encapsulatedBody == null ? 0 : encapsulatedBody.length) + '}';
    }
}
