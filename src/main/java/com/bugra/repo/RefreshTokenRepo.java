package com.bugra.repo;

import com.bugra.model.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface RefreshTokenRepo extends JpaRepository<RefreshToken, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    RefreshToken findByJti(String jti);

    @Modifying
    @Query("Delete from RefreshToken r where  r.jti = :jti")
    int deleteByJti(@Param("jti") String jti);

    @Modifying
    @Transactional
    @Query("Delete from RefreshToken r where r.expires <= :now")
    int deleteByExpires(@Param("now") long now);
}
