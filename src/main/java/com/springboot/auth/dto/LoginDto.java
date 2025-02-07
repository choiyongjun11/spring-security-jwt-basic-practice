package com.springboot.auth.dto;

import lombok.Getter;

//로그인 정보 역직렬화를 위한 LoginDto 클래스
@Getter
public class LoginDto {
    private String username;
    private String password;
}
