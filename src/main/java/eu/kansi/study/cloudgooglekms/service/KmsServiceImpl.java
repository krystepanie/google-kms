package eu.kansi.study.cloudgooglekms.service;

import com.google.cloud.ByteArray;
import com.google.cloud.kms.v1.AsymmetricDecryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.PublicKey;
import com.google.cloud.spring.kms.KmsTemplate;
import com.google.protobuf.ByteString;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import eu.kansi.study.cloudgooglekms.Scope;
import eu.kansi.study.cloudgooglekms.config.keys.KmsKeysProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;


@Service
@Slf4j
public class KmsServiceImpl implements KmsService {

    private final Environment environment;
    private final KmsTemplate kmsTemplate;

    private final KmsKeysProperties keysProperties;

    private final KeyManagementServiceClient keyManagementServiceClient;

    public KmsServiceImpl(Environment environment, KmsTemplate kmsTemplate, KmsKeysProperties keysProperties, KeyManagementServiceClient keyManagementServiceClient) {
        this.environment = environment;
        this.kmsTemplate = kmsTemplate;
        this.keysProperties = keysProperties;
        this.keyManagementServiceClient = keyManagementServiceClient;
    }

    @Override
    public String encrypt(String text, Scope scope) {
        byte[] encryptedBytes = kmsTemplate.encryptText(getSymmetricKeyPath(scope), text);
        return encode(encryptedBytes);
    }

    @Override
    public String decrypt(String text, Scope scope) {
        byte[] encryptedBytes = decode(text);
        return kmsTemplate.decryptText(getSymmetricKeyPath(scope), encryptedBytes);
    }

    public String decryptAsymmetric(String cipherText, Scope scope) {
        byte[] encryptedBytes = decode(cipherText);
        return new String(Base64.getEncoder().encode(decryptAsymmetric(encryptedBytes, scope)));
    }

    byte[] decryptAsymmetric(byte[] encryptedBytes, Scope scope) {
        String fullPath = getAsymmetricKeyFullPath(scope);
        AsymmetricDecryptResponse resp = keyManagementServiceClient.asymmetricDecrypt(fullPath, ByteString.copyFrom(encryptedBytes));
        return resp.getPlaintext().toByteArray();
    }

    @Override
    public PublicKey getPublicKey(Scope scope) {
        String fullPath = getAsymmetricKeyFullPath(scope);
        return keyManagementServiceClient.getPublicKey(fullPath);
    }

    @Override
    public String decryptJwe(String idToken, Scope scope) throws ParseException, JOSEException {
        JWEObject jwe = JWEObject.parse(idToken);
        jwe.decrypt(new JweDecrypterGcpKms(getCekDecrypter(scope), Collections.emptySet(), true));
        return jwe.toString();
    }

    private Function<Base64URL, ByteArray> getCekDecrypter(Scope scope) {
        return encryptedKey -> ByteArray.copyFrom(decryptAsymmetric(encryptedKey.decode(), scope));
    }

    @Override
    public String generateJwe(Scope scope) throws Exception {
        Date now = new Date();

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder().issuer("https://openid.net").subject("alice").audience(Arrays.asList("https://app-one.com", "https://app-two.com")).expirationTime(new Date(now.getTime() + 1000 * 60 * 10)) // expires in 10 minutes
                .notBeforeTime(now).issueTime(now).jwtID(UUID.randomUUID().toString()).build();

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

        RSAEncrypter encrypter = new RSAEncrypter(getPemPublicKey(scope));

        // Do the actual encryption
        jwt.encrypt(encrypter);

        // Serialise to JWT compact form
        String jwtString = jwt.serialize();

        log.info(jwtString);
        return jwtString;
    }

    RSAPublicKey getPemPublicKey(Scope scope) throws Exception {
        String temp = getPublicKey(scope).getPem();
        String publicKeyPEM = temp.lines()
                .filter(s -> !s.contains("PUBLIC KEY"))
                .collect(Collectors.joining());

        Base64.Decoder b64 = Base64.getDecoder();
        byte[] decoded = b64.decode(publicKeyPEM);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    String getSymmetricKeyPath(Scope scope) {
        KmsKeysProperties.KmsKey kmsKey = keysProperties.getKeys().get(scope.value());
        return String.format("%s/%s", kmsKey.getKeyRing(), kmsKey.getCryptoKey());
    }

    String getAsymmetricKeyFullPath(Scope scope) {
        return keysProperties.getKeys().get(scope.value()).getFullPathWithVersion();
    }

    private String encode(byte[] bytes) {
        return Base64URL.encode(bytes).toString();
    }

    private byte[] decode(String encryptedText) {
        return Base64URL.from(encryptedText).decode();
    }

}
