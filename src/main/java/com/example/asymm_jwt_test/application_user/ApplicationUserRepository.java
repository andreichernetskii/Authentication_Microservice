package com.example.asymm_jwt_test.application_user;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for accessing ApplicationUser entities in the database.
 */
@Repository
public interface ApplicationUserRepository extends MongoRepository<ApplicationUser, String> {
    Optional<ApplicationUser> findByEmail( String email );
    boolean existsByEmail( String email );
}