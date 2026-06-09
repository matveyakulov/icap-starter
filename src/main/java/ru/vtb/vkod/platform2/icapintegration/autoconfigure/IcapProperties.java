package ru.vtb.vkod.platform2.icapintegration.autoconfigure;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Externalized configuration for the ICAP starter, bound from properties/YAML under the {@code icap} prefix.
 *
 * <p>Example {@code application.yml}:</p>
 * <pre>{@code
 * icap:
 *   enabled: true
 *   host: icap.internal.example.com
 *   port: 1344
 *   service: avscan
 *   connect-timeout: 5s
 *   read-timeout: 30s
 *   allow-204: true
 *   tls: false
 *   preview:
 *     enabled: true
 *     size: 4096
 * }</pre>
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "icap")
public class IcapProperties {

    /** Whether the ICAP client auto-configuration is enabled. */
    private boolean enabled = true;

    /** Hostname or IP address of the ICAP server. */
    private String host = "localhost";

    /** TCP port of the ICAP server. The IANA-registered default ICAP port is 1344. */
    private int port = 1344;

    /**
     * Default ICAP service path/name to target (the part after the host in the ICAP URI, e.g.
     * {@code avscan} for {@code icap://host:1344/avscan}). Server/product specific.
     */
    private String service = "";

    /** TCP connect timeout. A value of zero means "wait indefinitely". */
    private Duration connectTimeout = Duration.ofSeconds(5);

    /** Socket read timeout for awaiting server data. A value of zero means "wait indefinitely". */
    private Duration readTimeout = Duration.ofSeconds(30);

    /**
     * Whether to advertise {@code Allow: 204}, permitting the server to answer "204 No Content"
     * (no modifications needed) instead of echoing back the whole body. Recommended for efficiency.
     */
    private boolean allow204 = true;

    /** Whether to connect using TLS (ICAPS) instead of plain TCP. */
    private boolean tls = false;

    /** ICAP {@code Preview} settings. */
    private final Preview preview = new Preview();

    /**
     * Settings for the ICAP {@code Preview} mechanism, which lets the server make an early decision from
     * just the first part of the body before the client streams the remainder.
     */
    @Getter
    @Setter
    public static class Preview {

        /** Whether to use the {@code Preview} mechanism when a body is present. */
        private boolean enabled = true;

        /** Number of leading body bytes to send as the preview. */
        private int size = 4096;
    }
}
