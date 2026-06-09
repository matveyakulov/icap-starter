package io.github.icap.spring.boot.autoconfigure;

import io.github.icap.spring.boot.client.DefaultIcapClient;
import io.github.icap.spring.boot.client.IcapClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

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
     * @param properties the bound ICAP properties
     * @return a configured {@link DefaultIcapClient}
     */
    @Bean
    @ConditionalOnMissingBean
    public IcapClient icapClient(IcapProperties properties) {
        return new DefaultIcapClient(
                properties.getHost(),
                properties.getPort(),
                properties.getService(),
                (int) properties.getConnectTimeout().toMillis(),
                (int) properties.getReadTimeout().toMillis(),
                properties.getPreview().isEnabled(),
                properties.getPreview().getSize(),
                properties.isAllow204(),
                properties.isTls());
    }
}
