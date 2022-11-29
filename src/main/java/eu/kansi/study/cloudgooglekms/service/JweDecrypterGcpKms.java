package eu.kansi.study.cloudgooglekms.service;

import com.google.cloud.ByteArray;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.crypto.impl.RSACryptoProvider;
import com.nimbusds.jose.crypto.impl.RSAKeyUtils;
import com.nimbusds.jose.util.Base64URL;
import eu.kansi.study.cloudgooglekms.Scope;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

public class JweDecrypterGcpKms extends RSACryptoProvider implements JWEDecrypter {

    private final CriticalHeaderParamsDeferral critPolicy;
    private final Function<Base64URL, ByteArray> cekDecrypter;
    private Exception cekDecryptionException;

    public JweDecrypterGcpKms(
            Function<Base64URL, ByteArray> cekDecrypter,
            Set<String> defCritHeaders,
            boolean allowWeakKey) {
        this.critPolicy = new CriticalHeaderParamsDeferral();
        this.cekDecrypter = cekDecrypter;
    }

    @Override
    public byte[] decrypt(JWEHeader header, Base64URL encryptedKey, Base64URL iv, Base64URL cipherText, Base64URL authTag) throws JOSEException {
        if (encryptedKey == null) {
            throw new JOSEException("Missing JWE encrypted key");
        } else if (iv == null) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        } else if (authTag == null) {
            throw new JOSEException("Missing JWE authentication tag");
        } else {
            this.critPolicy.ensureHeaderPasses(header);
            JWEAlgorithm alg = header.getAlgorithm();
            int keyLength = header.getEncryptionMethod().cekBitLength();

            SecretKey cek = getCek(encryptedKey);
            return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, this.getJCAContext());
        }
    }

    SecretKey getCek(Base64URL encryptedKey) {
        ByteArray cekValue = cekDecrypter.apply(encryptedKey);
        return new SecretKeySpec(cekValue.toByteArray(), "AES");
    }

    public Exception getCEKDecryptionException() {
        return this.cekDecryptionException;
    }

}
