package com.springboot.auth.handler;

import com.google.gson.Gson;
import com.springboot.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 로그인 인증 실패 시 추가 작업을 할 수 있는 MemberAuthenticationFailureHanlder 를 구현합니다.
@Slf4j
public class MemberAuthenticationFailureHandler implements AuthenticationFailureHandler { //추상 메서드를 불러옵니다.

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        log.error("# Authentication failed: {}", exception.getMessage());

        sendErrorResponse(response); //아래에 있는 sendErrorResponse() 메서드를 호출해 출력 스트림에 Error 정보를 담고 있다.

    }


    private void sendErrorResponse(HttpServletResponse response) throws IOException {
        //Error 정보가 담긴 객체(errorResponse)를 JSON 문자열로 변환하는데 사용되는 Gson 라이브러리의 인스턴스를 생성합니다.
        Gson gson = new Gson();
        ErrorResponse errorResponse = ErrorResponse.of(HttpStatus.UNAUTHORIZED); //http 401 상태코드 전달
        response.setContentType(MediaType.APPLICATION_JSON_VALUE); //클라이언트에게 알려줄수 있도록 http header에 추가합니다.
        response.setStatus(HttpStatus.UNAUTHORIZED.value()); //response 상태가 401임을 클라이언트에게 알려줄 수 있도록 합니다.
        //Gson을 이용해 errorResponse 객체를 JSON 포맷 문자열로 변환 후, 출력 스트림을 생성합니다.
        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));

    }

}
