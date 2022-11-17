package com.tutorial.jwt.repository;

import com.tutorial.jwt.entity.Users;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {
  /**
   * username을 기준으로 user 정보 + 인증 정보 조회
   *
   * @param username 검색할 username
   * @return Users
   */
  @EntityGraph(attributePaths = "authorities")
  // Eager 조회로 authorities 정보를 같이 조회해올 수 있게 한다.
  Optional<Users> findOneWithAuthoritiesByUsername(String username);
}
