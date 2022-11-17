package com.tutorial.jwt.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenDto {
  private String token;

  public TokenDto(String token) {
    this.token = token;
  }
}
