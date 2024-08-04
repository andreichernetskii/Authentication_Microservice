package com.example.asymm_jwt_test.config.jwt;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.stereotype.Component;

import java.security.*;

@Getter
@Component
public class KeyPairOnStartGenerator {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    private void setKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "RSA" );
        keyPairGenerator.initialize( 2048 );
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }
}
