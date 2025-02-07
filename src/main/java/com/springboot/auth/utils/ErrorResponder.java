package com.springboot.auth.utils;

import com.google.gson.Gson;
import com.springboot.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//ErrorResponder 클래스는 ErrorResponse를 출력 스트림으로 생성하는 역할을 합니다.
//에러 응답을 JSON 형태로 클라이언트에게 보내는 역할을 합니다.
public class ErrorResponder {
    //sendErrorResponse()라는 정적(static) 메서드를 제공하여 어디서든 쉽게 호출할 수 있습니다.
    //객체를 이용하여 http 응답, 상태코드를 생성합니다.
    public static void sendErrorResponse(HttpServletResponse response, HttpStatus status) throws IOException {
        //google의 Gson 라이브러리를 사용하여 객체를 JSON 문자열로 변환합니다.
        Gson gson = new Gson();
        //HTTP 상태코드 정보를 담은 errorResponse 객체 생성합니다.
        ErrorResponse errorResponse = ErrorResponse.of(status);
        //응답의 content-type을 json으로 설정합니다.
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        //전달받은 http 상태코드를 설정합니다.
        response.setStatus(status.value());
        //클라이언트에게 변환된 JSON 데이터를 응답으로 보내니다.
        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));

    }

}
