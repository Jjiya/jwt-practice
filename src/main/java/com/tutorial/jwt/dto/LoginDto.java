package com.tutorial.jwt.dto;

import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
public class LoginDto {
  @NotNull
  @Size(min = 3, max = 50)
  private String username;

  @NotNull
  @Size(min = 3, max = 100)
  private String password;

  public LoginDto(String username, String password) {
    this.username = username;
    this.password = password;
  }
}
