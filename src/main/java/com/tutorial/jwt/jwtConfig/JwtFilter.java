package com.tutorial.jwt.jwtConfig;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class JwtFilter extends GenericFilterBean {
  private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
  public static final String AUTHORIZATION_HEADER = "Authorization";

  private TokenProvider tokenProvider;

  public JwtFilter(TokenProvider tokenProvider) {
    this.tokenProvider = tokenProvider;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
//    request에서 token을 받아옴
    String jwt = resolveToken(httpServletRequest);
    String requestURI = httpServletRequest.getRequestURI();

//    token에 대한 유효성 검증
    if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
//      token이 정상 token이면
//      token에서 authentication를 받아오고
      Authentication authentication = tokenProvider.getAuthentication(jwt);
//      authentication를 SecurityContext에 저장 
      SecurityContextHolder.getContext().setAuthentication(authentication);

      logger.debug("Security context에 '{}' 인증 정보를 저장했습니다. uri: {}", authentication.getName(), requestURI);
    } else {
      logger.debug("유효한 JWT 토큰이 없습니다. uri: {}", requestURI);
    }

    chain.doFilter(request, response);
  }

  /**
   * RequestHeader에서 token 정보 꺼내오기 위함
   *
   * @param request request 요청
   * @return 토큰 정보
   */
  private String resolveToken(HttpServletRequest request) {
    String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7);
    }

    return null;
  }

}
