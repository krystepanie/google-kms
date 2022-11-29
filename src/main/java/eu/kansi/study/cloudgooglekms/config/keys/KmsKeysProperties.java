package eu.kansi.study.cloudgooglekms.config.keys;

import eu.kansi.study.cloudgooglekms.config.YamlPropertySourceFactory;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.util.Map;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "eu.kansi.kms")
@PropertySource(value = "classpath:keys.yml", factory = YamlPropertySourceFactory.class)
public class KmsKeysProperties {

    private Map<String, KmsKey> keys;

    @Getter
    @Setter
    @EqualsAndHashCode
    @ToString
    public static class KmsKey {
        private String project;
        private String location;
        private String keyRing;
        private String cryptoKey;
        private String cryptoKeyVersion;

        public String getFullPathWithVersion() {
            return String.format("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
                    project, location, keyRing, cryptoKey, cryptoKeyVersion);
        }

    }
}
