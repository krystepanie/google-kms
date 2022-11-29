package eu.kansi.study.cloudgooglekms.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;


@RequestMapping("kms/{scope}")
public interface KmsController {

    @GetMapping("encrypt")
    @Valid
    ResponseEntity<String> encrypt(
            @NotNull @RequestParam("text") String text,
            @NotNull @PathVariable("scope") String scope);

    @GetMapping("decrypt")
    ResponseEntity<String> decrypt(
            @NotNull @RequestParam("text") String text,
            @NotNull @PathVariable("scope") String scope);

    @GetMapping("asymmetric/decrypt")
    ResponseEntity<String> asymmetricDecrypt(
            @NotNull @RequestParam("text") String text,
            @NotNull @PathVariable("scope") String scope);

    @GetMapping("public-key")
    ResponseEntity<String> getPublicKey(@NotNull @PathVariable("scope") String scope);

    @GetMapping("jwe/generate")
    ResponseEntity<String> generateJwe(@NotNull @PathVariable("scope") String scope) throws Exception;

    @Valid
    @GetMapping("jwe/decrypt")
    ResponseEntity<String> decryptJwe(
            @NotNull@RequestParam("jwe") String jwe,
            @NotNull @PathVariable("scope") String scooe) throws Exception;

}
