package ru.vtb.vkod.platform2.icapintegration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Opt-in Spring configuration that starts an in-process {@link IcapTestServer} when
 * {@code icap.test-server.enabled=true}. Intended for test stands &mdash; it lets a Spring Boot application
 * host an ICAP endpoint so a client can be pointed at {@code localhost:<port>} without a real appliance.
 *
 * <p>This is deliberately <strong>not</strong> registered as a Spring Boot auto-configuration (it is not
 * listed in the starter's {@code AutoConfiguration.imports}), so the published client starter is unchanged.
 * Enable it explicitly in your application/stand profile:</p>
 *
 * <pre>{@code
 * @Import(IcapTestServerConfiguration.class)
 * @SpringBootApplication
 * public class StandApplication { ... }
 * }</pre>
 *
 * <p>The server is wrapped in a {@link SmartLifecycle} bean so it binds its socket when the application
 * context starts and is closed cleanly on shutdown.</p>
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(IcapTestServerProperties.class)
@ConditionalOnProperty(prefix = "icap.test-server", name = "enabled", havingValue = "true")
public class IcapTestServerConfiguration {

    /**
     * Creates the (not-yet-started) test server from the bound properties. Exposed as its own bean so tests
     * can inject it and flip {@link IcapTestServer#setCheckPasses(boolean)} or read the bound port.
     *
     * @param properties the bound test-server properties
     * @return a configured, stopped {@link IcapTestServer}
     */
    @Bean
    @ConditionalOnMissingBean
    public IcapTestServer icapTestServer(IcapTestServerProperties properties) {
        return new IcapTestServer(properties.getPort(), properties.isCheckPasses());
    }

    /**
     * Binds the server's lifecycle to the application context: started on refresh, stopped on shutdown.
     *
     * @param server the test server bean
     * @return a {@link SmartLifecycle} managing {@code server}
     */
    @Bean
    public SmartLifecycle icapTestServerLifecycle(IcapTestServer server) {
        return new IcapTestServerLifecycle(server);
    }

    /** Adapts {@link IcapTestServer}'s {@code start()}/{@code close()} to Spring's {@link SmartLifecycle}. */
    static final class IcapTestServerLifecycle implements SmartLifecycle {

        private final IcapTestServer server;

        IcapTestServerLifecycle(IcapTestServer server) {
            this.server = server;
        }

        @Override
        public void start() {
            try {
                server.start();
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to start ICAP test server", e);
            }
        }

        @Override
        public void stop() {
            server.close();
        }

        @Override
        public boolean isRunning() {
            return server.isRunning();
        }
    }
}
