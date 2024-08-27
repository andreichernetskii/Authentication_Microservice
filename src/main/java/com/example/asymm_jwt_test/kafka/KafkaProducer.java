package com.example.asymm_jwt_test.kafka;

import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class KafkaProducer {

    private final KafkaTemplate<String, String> kafkaTemplate;

    public void sendPublicKey( PublicKey publicKey ) {
        for ( int i = 0; i < 2; i++ ) {
            kafkaTemplate.send( "public_key_distribution", i, "message" + i, Base64.getEncoder().encodeToString(publicKey.getEncoded()) );
        }
    }
}
