package eu.kansi.study.cloudgooglekms.service;


import com.google.cloud.kms.v1.PublicKey;
import com.nimbusds.jose.JOSEException;
import eu.kansi.study.cloudgooglekms.Scope;

import java.text.ParseException;

public interface KmsService {

    String encrypt(String string, Scope scope);

    String decrypt(String string, Scope scope);

    String decryptAsymmetric(String cipherText, Scope scope);

    PublicKey getPublicKey(Scope scope);

    String generateJwe(Scope scope) throws Exception;

    String decryptJwe(String jwe, Scope scope) throws ParseException, JOSEException;

}
