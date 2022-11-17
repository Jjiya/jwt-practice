package com.tutorial.jwt.config;

import com.tutorial.jwt.jwtConfig.JwtAccessDeniedHandler;
import com.tutorial.jwt.jwtConfig.JwtAuthenticationEntryPoint;
import com.tutorial.jwt.jwtConfig.JwtSecurityConfig;
import com.tutorial.jwt.jwtConfig.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity  // <<기본적인 web 보안 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true)  // @PreAuthorize annotation을 method 단위로 추가하기 위함
public class SecurityConfig extends WebSecurityConfigurerAdapter {
  private final TokenProvider tokenProvider;
  //  private final CorsFilter corsFilter;
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

  public SecurityConfig(
      TokenProvider tokenProvider,
//      CorsFilter corsFilter,
      JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
      JwtAccessDeniedHandler jwtAccessDeniedHandler
  ) {
    this.tokenProvider = tokenProvider;
//    this.corsFilter = corsFilter;
    this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().antMatchers("/h2-console/**"
        , "/favicon.ico"
        , "/error");
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        // token을 사용하는 방식이기 때문에 csrf를 disable합니다.
        .csrf().disable()

//        .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

//        custom exception handler 추가
        .exceptionHandling()
        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
        .accessDeniedHandler(jwtAccessDeniedHandler)

        // enable h2-console
        .and()
        .headers()
        .frameOptions()
        .sameOrigin()

        // 세션을 사용하지 않기 때문에 STATELESS로 설정
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

//        token이 없어도 api 요청을 할 수 있는 url
        .and()
        .authorizeRequests()
        .antMatchers("/api/hello").permitAll()
        .antMatchers("/api/authenticate").permitAll()
        .antMatchers("/api/signup").permitAll()

        .anyRequest().authenticated()

        .and()
        .apply(new JwtSecurityConfig(tokenProvider));

    return httpSecurity.build();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()  //httpServletRequest를 사용하는 요청들에 대한 접근 제한 설정
        .antMatchers("/api/hello").permitAll()  // 인증 없이 접근 가능할 경로 설정
        .anyRequest().authenticated();  //나머지 요청은 인증을 받아야함을 의미
  }
}