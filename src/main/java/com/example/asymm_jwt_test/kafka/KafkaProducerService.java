package com.example.asymm_jwt_test.kafka;

import org.springframework.kafka.support.SendResult;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

@Service
@RequiredArgsConstructor
public class KafkaProducerService {

    private static final Logger logger = LoggerFactory.getLogger( KafkaProducerService.class );

    @Value( value = "${kafka.producer.topic.public-key}" )
    private String publicKeyTopicName;

    private final KafkaTemplate<String, String> publicKeyKafkaTemplate;

    public void sendPublicKey( PublicKey publicKey ) {
        String encodedPublicKey = Base64.getEncoder().encodeToString( publicKey.getEncoded() );


        for ( int partition = 0; partition < 2; partition++ ) {
            CompletableFuture<SendResult<String, String>> future =
                    this.publicKeyKafkaTemplate.send( publicKeyTopicName, partition, null, encodedPublicKey );

            future.whenComplete( ( result, throwable ) -> {
                if ( throwable != null ) {
                    logger.error( "Unnable to send public key", throwable );
                } else {
                    logger.info( "Public key: " + encodedPublicKey );
                }
            } );
        }
    }
}
