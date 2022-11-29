package eu.kansi.study.cloudgooglekms.config;

import com.google.cloud.spring.core.Credentials;
import com.google.cloud.spring.core.CredentialsSupplier;
import com.google.cloud.spring.core.GcpScope;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@ConfigurationProperties("spring.cloud.gcp.kms")
public class GcpKmsProperties implements CredentialsSupplier {

    /**
     * Overrides the GCP OAuth2 credentials specified in the Core module.
     */
    @NestedConfigurationProperty
    private final Credentials credentials = new Credentials(GcpScope.CLOUD_PLATFORM.getUrl());

    /**
     * Overrides the GCP Project ID specified in the Core module.
     */
    private String projectId;

    @Override
    public Credentials getCredentials() {
        return credentials;
    }

    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

}

