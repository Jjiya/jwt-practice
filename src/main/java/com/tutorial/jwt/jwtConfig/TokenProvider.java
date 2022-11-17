package com.tutorial.jwt.jwtConfig;

import com.tutorial.jwt.entity.Users;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {
  private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
  private static final String AUTHORITIES_KEY = "auth";

  private final String secret;
  private final long tokenValidityInMs;

  private Key key;

  public TokenProvider(@Value("${jwt.secret}") String secret, @Value("${jwt.token-validity-in-seconds}") long tokenValidityInMs) {
    this.secret = secret;
    this.tokenValidityInMs = tokenValidityInMs * 1000;
  }

  /**
   * bean이 생성되고 di된 이후 secret 값을 Base64 Decode해서 key 변수에 할당하기 위함
   *
   * @throws Exception
   */
  @Override
  public void afterPropertiesSet() throws Exception {
    byte[] keyBytes = Decoders.BASE64.decode(secret);
    this.key = Keys.hmacShaKeyFor(keyBytes);
  }

  /**
   * Authentication 객체의 권한정보를 이용해 token을 생성
   *
   * @param authentication 권한 정보
   * @return jwt token
   */
  public String createToken(Authentication authentication) {
    String authorities = authentication.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(","));

    long now = new Date().getTime();
    Date validity = new Date(now + this.tokenValidityInMs);

    return Jwts.builder()
        .setSubject(authentication.getName())
        .claim(AUTHORITIES_KEY, authorities)
        .signWith(key, SignatureAlgorithm.HS512)
        .setExpiration(validity)
        .compact();
  }

  /**
   * token에 담겨있는 정보를 이용해 Authentication 객체를 반환
   *
   * @param token authentication 객체로 변환할 jwt token 값
   * @return
   */
  public Authentication getAuthentication(String token) {
    Claims claims = Jwts
        .parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token)
        .getBody();

    Collection<? extends GrantedAuthority> authorities =
        Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

    Users principal = new Users(claims.getSubject(), "", authorities);

    return new UsernamePasswordAuthenticationToken(principal, token, authorities);
  }

  /**
   * token의 유효성 검증
   * @param token
   * @return
   */
  public boolean validateToken(String token) {
    try {
      Jwts.parserBuilder()
          .setSigningKey(key).build()
          .parseClaimsJws(token);

      return true;
      
    } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException exception) {
      logger.info("잘못된 JWT 서명입니다.");
    } catch (ExpiredJwtException expiredJwtException) {
      logger.info("만료된 JWT 토큰입니다.");
    } catch (UnsupportedJwtException unsupportedJwtException) {
      logger.info("지원되지 않는 JWT 토근입니다.");
    } catch (IllegalArgumentException illegalArgumentException) {
      logger.info("JWT 토큰이 잘못되었습니다.");
    }

    return false;
  }
}
