package com.example.asymm_jwt_test.kafka;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KafkaConfiguration {

    @Bean
    public NewTopic newTopic() {
        return new NewTopic( "public_key_distribution", 2, ( short ) 1 );
    }
}
