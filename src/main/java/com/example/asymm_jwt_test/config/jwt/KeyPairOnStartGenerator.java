package com.example.asymm_jwt_test.config.jwt;

import com.example.asymm_jwt_test.kafka.KafkaProducerService;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.*;

@Getter
@Component
@RequiredArgsConstructor
public class KeyPairOnStartGenerator {
    private final KafkaProducerService kafkaProducer;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    private void initKeysAndSendPublicKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "RSA" );
        keyPairGenerator.initialize( 2048 );
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        kafkaProducer.sendPublicKey( getPublicKey() );
    }
}
