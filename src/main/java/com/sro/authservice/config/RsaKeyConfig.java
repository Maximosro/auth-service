package com.sro.authservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaKeyConfig {

    @Value("${auth.jwt.private-key-path}")
    private Path privateKeyPath;

    @Value("${auth.jwt.public-key-path}")
    private Path publicKeyPath;

    @Bean
    public KeyPair rsaKeyPair() {
        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            return loadKeys();
        }
        return generateAndSaveKeys();
    }

    @Bean
    public RSAPrivateKey rsaPrivateKey(KeyPair rsaKeyPair) {
        return (RSAPrivateKey) rsaKeyPair.getPrivate();
    }

    @Bean
    public RSAPublicKey rsaPublicKey(KeyPair rsaKeyPair) {
        return (RSAPublicKey) rsaKeyPair.getPublic();
    }

    private KeyPair loadKeys() {
        try {
            String privatePem = Files.readString(privateKeyPath);
            String publicPem = Files.readString(publicKeyPath);

            byte[] privateBytes = Base64.getDecoder().decode(
                    privatePem
                            .replace("-----BEGIN PRIVATE KEY-----", "")
                            .replace("-----END PRIVATE KEY-----", "")
                            .replaceAll("\\s", ""));
            byte[] publicBytes = Base64.getDecoder().decode(
                    publicPem
                            .replace("-----BEGIN PUBLIC KEY-----", "")
                            .replace("-----END PUBLIC KEY-----", "")
                            .replaceAll("\\s", ""));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return new KeyPair(
                    keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes)),
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes)));
        } catch (Exception e) {
            throw new RuntimeException("Failed to load RSA keys", e);
        }
    }

    private KeyPair generateAndSaveKeys() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            Files.createDirectories(privateKeyPath.getParent());

            String privatePem = "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded())
                    + "\n-----END PRIVATE KEY-----\n";
            String publicPem = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";

            Files.writeString(privateKeyPath, privatePem);
            Files.writeString(publicKeyPath, publicPem);

            return keyPair;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA keys", e);
        }
    }
}
