package com.example.asymm_jwt_test.application_user;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for accessing ApplicationUser entities in the database.
 */
@Repository
public interface ApplicationUserRepository extends MongoRepository<ApplicationUser, String> {

    Optional<ApplicationUser> findByEmail( @Param( "email" ) String email );
    Boolean existsByEmail( @Param( "email" ) String email );
}