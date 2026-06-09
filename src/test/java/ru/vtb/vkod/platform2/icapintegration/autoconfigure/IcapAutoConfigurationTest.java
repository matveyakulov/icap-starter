package ru.vtb.vkod.platform2.icapintegration.autoconfigure;

import ru.vtb.vkod.platform2.icapintegration.client.IcapClient;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the Spring Boot auto-configuration contract: a single {@link IcapClient} is registered by
 * default, the {@code icap.*} properties are bound, and the client can be disabled.
 */
class IcapAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IcapAutoConfiguration.class));

    @Test
    void registersIcapClientByDefault() {
        runner.run(context -> assertThat(context).hasSingleBean(IcapClient.class));
    }

    @Test
    void bindsProperties() {
        runner.withPropertyValues(
                "icap.host=icap.example.com",
                "icap.port=11344",
                "icap.service=avscan",
                "icap.preview.size=8192"
        ).run(context -> {
            assertThat(context).hasSingleBean(IcapProperties.class);
            IcapProperties props = context.getBean(IcapProperties.class);
            assertThat(props.getHost()).isEqualTo("icap.example.com");
            assertThat(props.getPort()).isEqualTo(11344);
            assertThat(props.getService()).isEqualTo("avscan");
            assertThat(props.getPreview().getSize()).isEqualTo(8192);
        });
    }

    @Test
    void canBeDisabled() {
        runner.withPropertyValues("icap.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(IcapClient.class));
    }

    @Test
    void backsOffWhenUserProvidesOwnClient() {
        runner.withUserConfiguration(CustomClientConfig.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(IcapClient.class);
                    assertThat(context.getBean(IcapClient.class)).isInstanceOf(CustomClientConfig.NoopClient.class);
                });
    }

    /** A user-supplied client bean that should take precedence over the auto-configured one. */
    static class CustomClientConfig {
        @org.springframework.context.annotation.Bean
        IcapClient icapClient() {
            return new NoopClient();
        }

        static class NoopClient implements IcapClient {
            public ru.vtb.vkod.platform2.icapintegration.model.IcapResponse options(String service) {
                return null;
            }

            public ru.vtb.vkod.platform2.icapintegration.model.IcapResponse reqmod(ru.vtb.vkod.platform2.icapintegration.model.IcapRequest request) {
                return null;
            }

            public ru.vtb.vkod.platform2.icapintegration.model.IcapResponse respmod(ru.vtb.vkod.platform2.icapintegration.model.IcapRequest request) {
                return null;
            }

            public ru.vtb.vkod.platform2.icapintegration.model.IcapResponse scan(byte[] content, String filename) {
                return null;
            }
        }
    }
}
