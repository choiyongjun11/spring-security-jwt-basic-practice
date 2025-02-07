package com.springboot.auth.handler;

import com.springboot.auth.utils.ErrorResponder;
import com.springboot.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 스프링 시큐리티에서 인증되지 않은 사용자 401에러 요청을 처리하는 클래스 입니다.
// 로그인이 필요한 API에 인증 없이 접근할 때 실행됩니다.
// 인증 예외 처리 클래스, 401 에러 예외 발생 시 실행되는 인터페이스
// 사용자가 인증되지 않은 상태에서 보호된 리소스에 접근할 때 실행됩니다.
public class MemberAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        //commence() 메서드는 스프링 시큐리티에서 인증 예외가 발생할 때 자동으로 호출합니다.
        Exception exception = (Exception) request.getAttribute("exception");
        //예외 객체를 가져옵니다. 만약 필터 체인에서 예외가 발생했다면, 해당 예외를 가져올수 있습니다.
        ErrorResponder.sendErrorResponse(response, HttpStatus.UNAUTHORIZED);
        //클라이언트에게 401 응답 에러를 보냅니다.
    }
}
