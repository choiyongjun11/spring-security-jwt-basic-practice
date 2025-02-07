package com.springboot.auth.handler;

import com.springboot.auth.utils.ErrorResponder;
import com.springboot.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/*
MemberAccessDeniedHandler 클래스는 요청한 리소스에 대해 적절한 권한이 없으면 호출되는 핸들러로서,
처리학자 하는 로직을 handle() 메서드에 구현하면 됩니다.
적절한 권한인지 확인하는 과정에서 AccessDeniedException 이 발생하면 ErrorResponse를 생성해서 클라이언트에게 전송합니다.
 */

@Slf4j
@Component
public class MemberAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ErrorResponder.sendErrorResponse(response, HttpStatus.FORBIDDEN);
        log.warn("Forbidden error happened: {}", accessDeniedException.getMessage());


    }
}
