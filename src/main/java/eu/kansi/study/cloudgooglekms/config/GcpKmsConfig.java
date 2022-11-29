package eu.kansi.study.cloudgooglekms.config;

import com.google.api.gax.core.CredentialsProvider;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.cloud.spring.core.GcpProjectIdProvider;
import com.google.cloud.spring.core.UserAgentHeaderProvider;
import com.google.cloud.spring.kms.KmsTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;


@Slf4j
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({GcpProperties.class, GcpKmsProperties.class})
@ConditionalOnClass({KeyManagementServiceClient.class, KmsTemplate.class})
@ConditionalOnProperty(value = "spring.cloud.gcp.kms.enabled", matchIfMissing = true)
public class GcpKmsConfig {

    private final CredentialsProvider credentialsProvider;

    private final GcpProjectIdProvider gcpProjectIdProvider;

    public GcpKmsConfig(CredentialsProvider credentialsProvider, GcpProjectIdProvider gcpProjectIdProvider) {
        this.credentialsProvider = credentialsProvider;
        this.gcpProjectIdProvider = gcpProjectIdProvider;
    }


    @Bean
    @ConditionalOnMissingBean
    public KeyManagementServiceClient keyManagementClient(CredentialsProvider googleCredentials)
            throws IOException {
        KeyManagementServiceSettings settings =
                KeyManagementServiceSettings.newBuilder()
                        .setCredentialsProvider(this.credentialsProvider)
                        .setHeaderProvider(new UserAgentHeaderProvider(GcpKmsConfig.class))
                        .build();

        return KeyManagementServiceClient.create(settings);
    }

    @Bean
    @ConditionalOnMissingBean
    public KmsTemplate kmsTemplate(KeyManagementServiceClient client) {
        return new KmsTemplate(client, gcpProjectIdProvider);
    }
}
