package com.sistemasactivos.ms.accessmgt.repository;

import com.sistemasactivos.ms.accessmgt.model.User;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends BaseRepository<User, Integer>{
    Optional<User> findOneByEmail(String email);
}
