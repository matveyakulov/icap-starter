package ru.vtb.vkod.platform2.icapintegration.autoconfigure;

import ru.vtb.vkod.platform2.icapintegration.client.DefaultIcapClient;
import ru.vtb.vkod.platform2.icapintegration.client.IcapClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

    @Test
    void usesNamedSslBundleForTls() throws Exception {
        SslBundles bundles = new DefaultSslBundleRegistry("icap", emptyTrustOnlyBundle());

        IcapProperties properties = new IcapProperties();
        properties.getSsl().setEnabled(true);
        properties.getSsl().setBundle("icap");

        IcapClient client = new IcapAutoConfiguration().icapClient(properties, providerOf(bundles));

        // No exception means the bundle's SSL context was resolved and handed to the client.
        assertThat(client).isInstanceOf(DefaultIcapClient.class);
    }

    @Test
    void failsFastWhenNamedSslBundleIsMissing() {
        SslBundles bundles = new DefaultSslBundleRegistry(); // no bundles registered

        IcapProperties properties = new IcapProperties();
        properties.getSsl().setEnabled(true);
        properties.getSsl().setBundle("nope");

        assertThatThrownBy(() -> new IcapAutoConfiguration().icapClient(properties, providerOf(bundles)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("nope");
    }

    /** An SSL bundle backed by an empty in-memory PKCS#12 trust store (enough to build an SSL context). */
    private static SslBundle emptyTrustOnlyBundle() throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        return SslBundle.of(SslStoreBundle.of(null, null, trustStore));
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<SslBundles> providerOf(SslBundles bundles) {
        ObjectProvider<SslBundles> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(bundles);
        return provider;
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
