package com.springboot.auth.filter;

import com.springboot.auth.AuthorityUtils;
import com.springboot.auth.jwt.JwtTokenizer;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class JwtVerificaitonFilter extends OncePerRequestFilter {
    private final JwtTokenizer jwtTokenizer;
    private final AuthorityUtils authorityUtils;

    public JwtVerificaitonFilter(JwtTokenizer jwtTokenizer, AuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        /*
        예외 처리 로직은 다음과 같습니다.
        try~catch 문으로 특정 예외 타입의 Exception이 catch 되면 해당 Exception을
        request.setAttribute("exception", Exception 객체) 와 같이 HttpServletRequest의 애트리뷰트로 추가됩니다.

        JwtVerificationFilter 예외 처리의 키포인트는 우리가 일반적으로 알고 있는 예외 처리 방식과는 다르게
         Exception을 catch한 후에 Exception을 다시 throw 한다든지 하는 처리를 하지 않고,
         단순히 request.setAttribute()를 설정하는 일밖에 하지 않는다는 것입니다.
         예외가 발생하게 되면 SecurityContext에 클라이언트의 인증 정보가 저장되지 않습니다.

         SecurityContext에 클라이언트의 인증 정보가 저장되지 않은 상태로 다음 Security Filter 로직을 수행하다 보면
         결국에는 Filter 내부에서 AuthenticationException이 발생하게 되고,
         이 AuthenticationException은 바로 아래에서 설명하는 AuthenticationEntryPoint가 처리하게 됩니다.

         SecurityContext에 클라이언트의 인증 정보가 채워지지 않은 상태에서 Security Filter 로직을 수행하게 되면
          Security Filter 체인의 Filter 내부에서  AuthenticationException이 발생한다는 사실이다.
         */

        try {
            Map<String, Object> claims = verifyJws(request);
            setAuthenticationToContext(claims);
        } catch (SignatureException se) {
            request.setAttribute("exception", se);
        } catch (ExpiredJwtException ee) {
            request.setAttribute("exception", ee);
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }

        filterChain.doFilter(request, response);

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        String authorization = request.getHeader("Authorization");
        return authorization == null || !authorization.startsWith("Bearer");
    }

    private Map<String, Object> verifyJws(HttpServletRequest request) {
        String jws = request.getHeader("Authorization").replace("Bearer ", "");
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());
        Map<String, Object> claims = jwtTokenizer.getClaims(jws, base64EncodedSecretKey).getBody();

        return claims;

    }

    private void setAuthenticationToContext(Map<String, Object> claims) {
        String username = (String) claims.get("username");
        List<GrantedAuthority> authorities = authorityUtils.createAuthorities((List)claims.get("roles"));
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

}
