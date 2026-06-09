package ru.vtb.vkod.platform2.icapintegration.autoconfigure;

import ru.vtb.vkod.platform2.icapintegration.client.DefaultIcapClient;
import ru.vtb.vkod.platform2.icapintegration.client.IcapClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.NoSuchSslBundleException;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.util.StringUtils;

import javax.net.ssl.SSLSocketFactory;

/**
 * Auto-configuration that exposes a ready-to-use {@link IcapClient} bean built from {@link IcapProperties}.
 *
 * <p>Activated automatically when this starter is on the classpath, unless {@code icap.enabled=false}. A
 * consumer may supply their own {@link IcapClient} bean to override the default (thanks to
 * {@link ConditionalOnMissingBean}).</p>
 *
 * <p>Registered via {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}
 * (the Spring Boot 2.7+/3.x auto-configuration import mechanism).</p>
 */
@AutoConfiguration
@EnableConfigurationProperties(IcapProperties.class)
@ConditionalOnProperty(prefix = "icap", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IcapAutoConfiguration {

    /**
     * Creates the default {@link IcapClient} from the bound {@link IcapProperties}. Durations are converted
     * to milliseconds for the socket layer; a duration of zero maps to "no timeout".
     *
     * <p>When TLS is enabled, the {@link SSLSocketFactory} comes from the Spring SSL bundle named by
     * {@code icap.ssl.bundle} ({@code spring.ssl.bundle.*}); if no bundle is named, the JVM default SSL
     * context is used.</p>
     *
     * @param properties the bound ICAP properties
     * @param sslBundles the application's SSL bundles, if any (used when {@code icap.ssl.bundle} is set)
     * @return a configured {@link DefaultIcapClient}
     */
    @Bean
    @ConditionalOnMissingBean
    public IcapClient icapClient(IcapProperties properties, ObjectProvider<SslBundles> sslBundles) {
        IcapProperties.Ssl ssl = properties.getSsl();
        SSLSocketFactory sslSocketFactory = ssl.isEnabled()
                ? resolveSslSocketFactory(ssl, sslBundles)
                : null;
        return new DefaultIcapClient(
                properties.getHost(),
                properties.getPort(),
                properties.getService(),
                (int) properties.getConnectTimeout().toMillis(),
                (int) properties.getReadTimeout().toMillis(),
                properties.getPreview().isEnabled(),
                properties.getPreview().getSize(),
                properties.isAllow204(),
                ssl.isEnabled(),
                sslSocketFactory);
    }

    /**
     * Resolves the TLS socket factory for an enabled {@link IcapProperties.Ssl} configuration. Returns
     * {@code null} when no bundle is named, letting the client fall back to the JVM default SSL context.
     */
    private SSLSocketFactory resolveSslSocketFactory(IcapProperties.Ssl ssl, ObjectProvider<SslBundles> sslBundles) {
        if (!StringUtils.hasText(ssl.getBundle())) {
            return null;
        }
        SslBundles bundles = sslBundles.getIfAvailable();
        if (bundles == null) {
            throw new IllegalStateException(
                    "icap.ssl.bundle='" + ssl.getBundle() + "' is set but no SslBundles bean is available; "
                            + "define the bundle under spring.ssl.bundle.*");
        }
        try {
            return bundles.getBundle(ssl.getBundle()).createSslContext().getSocketFactory();
        } catch (NoSuchSslBundleException e) {
            throw new IllegalStateException(
                    "ICAP SSL bundle '" + ssl.getBundle() + "' is not defined under spring.ssl.bundle.*", e);
        }
    }
}
