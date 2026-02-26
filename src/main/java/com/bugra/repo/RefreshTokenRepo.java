package com.bugra.repo;

import com.bugra.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshToken, String> {



    @Modifying
    @Query("Update RefreshToken t set t.revoked = true where t.jti = :jti and t.revoked = false")
    int revokeTokenByJti(@Param("jti") String jti);

    @Query("Select t.revoked from RefreshToken t where t.jti = :jti")
    boolean isTokenRevoked(@Param("jti") String jti);
}