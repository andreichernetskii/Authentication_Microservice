package com.example.asymm_jwt_test.kafka;

import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.tomcat.util.codec.binary.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class KafkaProducerConfig {

    @Value( value = "${spring.kafka.bootstrap-servers}" )
    private String bootstrapAddress;

    @Bean
    public ProducerFactory<String, String> publicKeyProducerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put( ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapAddress );
        props.put( ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class );
        props.put( ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class );

        return new DefaultKafkaProducerFactory<>( props );
    }

    @Bean
    public KafkaTemplate<String, String> publicKeyKafkaTemplate() {
        return new KafkaTemplate<>( publicKeyProducerFactory() );
    }

    @Bean
    public NewTopic newTopic() {
        return new NewTopic( "public_key_distribution", 2, ( short ) 1 );
    }
}
