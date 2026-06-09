package ru.vtb.vkod.platform2.icapintegration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Externalized configuration for the embedded {@link IcapTestServer}, bound from properties/YAML under the
 * {@code icap.test-server} prefix.
 *
 * <p>The test server is an in-process ICAP listener used to exercise the client (or any ICAP consumer) on a
 * stand without a real antivirus/DLP appliance. It is <strong>disabled by default</strong> &mdash; switch it
 * on explicitly only in test/stand profiles.</p>
 *
 * <p>This class lives outside the starter's production auto-configuration on purpose: it is wired in
 * manually via {@link IcapTestServerConfiguration} (see {@code @Import}) so the published client starter is
 * never altered. Plain getters/setters are used (no Lombok) to keep the {@code server} package
 * self-contained.</p>
 *
 * <p>Example {@code application.yml}:</p>
 * <pre>{@code
 * icap:
 *   test-server:
 *     enabled: true
 *     port: 1344
 *     check-passes: true   # true = scans report "clean"; false = scans report "infected/blocked"
 * }</pre>
 */
@ConfigurationProperties(prefix = "icap.test-server")
public class IcapTestServerProperties {

    /** Whether to start the embedded ICAP test server. Off by default; enable only on test stands. */
    private boolean enabled = false;

    /** TCP port the test server binds. {@code 0} lets the OS pick an ephemeral port. */
    private int port = 1344;

    /**
     * The verdict the test server returns for scanned content. When {@code true} the check "passes" and the
     * server answers {@code 204 No Content} (clean); when {@code false} every request fails the check and the
     * server answers {@code 200 OK} with an {@code X-Infection-Found} "blocked" response. (The EICAR test
     * signature is always treated as infected regardless of this flag.)
     */
    private boolean checkPasses = true;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public boolean isCheckPasses() {
        return checkPasses;
    }

    public void setCheckPasses(boolean checkPasses) {
        this.checkPasses = checkPasses;
    }
}
