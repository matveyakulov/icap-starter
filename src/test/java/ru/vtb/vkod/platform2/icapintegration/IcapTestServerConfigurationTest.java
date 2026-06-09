package ru.vtb.vkod.platform2.icapintegration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the opt-in ICAP test-server configuration: it is off by default, starts when enabled, and binds
 * the {@code check-passes} verdict flag.
 */
class IcapTestServerConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(IcapTestServerConfiguration.class);

    @Test
    void offByDefault() {
        runner.run(context -> assertThat(context).doesNotHaveBean(IcapTestServer.class));
    }

    @Test
    void startsServerWhenEnabled() {
        runner.withPropertyValues(
                "icap.test-server.enabled=true",
                "icap.test-server.port=0" // ephemeral, avoids clashing with anything bound to 1344
        ).run(context -> {
            assertThat(context).hasSingleBean(IcapTestServer.class);
            IcapTestServer server = context.getBean(IcapTestServer.class);
            assertThat(server.isRunning()).isTrue();
            assertThat(server.getPort()).isGreaterThan(0);
        });
    }

    @Test
    void bindsCheckPassesFlag() {
        runner.withPropertyValues(
                "icap.test-server.enabled=true",
                "icap.test-server.port=0",
                "icap.test-server.check-passes=false"
        ).run(context -> {
            IcapTestServer server = context.getBean(IcapTestServer.class);
            assertThat(server.isCheckPasses()).isFalse();
        });
    }
}
