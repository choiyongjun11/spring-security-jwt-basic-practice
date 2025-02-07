package com.springboot.config;

import com.springboot.auth.AuthorityUtils;
import com.springboot.auth.filter.JwtAuthenticationFilter;
import com.springboot.auth.filter.JwtVerificaitonFilter;
import com.springboot.auth.handler.MemberAccessDeniedHandler;
import com.springboot.auth.handler.MemberAuthenticationEntryPoint;
import com.springboot.auth.handler.MemberAuthenticationFailureHandler;
import com.springboot.auth.handler.MemberAuthenticationSuccessHandler;
import com.springboot.auth.jwt.JwtTokenizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {

    private final JwtTokenizer jwtTokenizer;
    private final AuthorityUtils authorityUtils;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer, AuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // h2 자체가 내부적으로 <frame> 태그를 사용하고 있기 때문에
                // 개발환경에서는 h2 웹 콘솔을 정상적으로 사용할 수 있도록 .frameoptions().sameOrigin 추가 합니다.
                .headers().frameOptions().sameOrigin() // 1.호출하면 동일 출처로부터 들어오는 request만 페이지 렌더링을 허용합니다.
                .and()
                .csrf().disable() // 2. CSRF(Cross-site Reqeust Forgery) 공격에 대한 spring security에 대한 설정을 비활성화 합니다.
                // 설정하지 않으면 403 에러로 인해 정상적인 접속이 불가능합니다.
                .cors(withDefaults()) // 3.  CORS 설정을 추가합니다. defaults 일 경우. corsConfigurationSource 라는 이름으로 등록된 Bean을 이용한다.
                /*
             CORS를 처리하는 가장 쉬운 방법은 CorsFilter를 사용하는 것이다. CorsConfigurationSource Bean을 제공함으로써 CorsFilter 적용 가능.
             ORS(Cross-Origin Resource Sharing)이란?

             애플리케이션 간에 출처(Origin)가 다를 경우 스크립트 기반의 HTTP 통신을 통한 리소스 접근이 제한되는데,
             CORS는 출처가 다른 스크립트 기반 http 통신을 하더라도 선택적으로 리소스에 접근할 수 있는 권한을 부여하도록
             브라우저에 알려주는 정책입니다.

             plus)
             로컬 환경에서 postman을 사용하여 애플리케이션의 엔드포인트를 호출할 경우에는 cors 설정이 필요 없다.
             하지만, 프론트엔드 웹앱과의 http 통신에서 에러를 만나게 될 수 있으므로 사전 학습 차원에서 설정했다.
              */
                //웹 페이지는 CSR 방식으로 사용하고자 합니다. JSON 형태로 데이터를 주고 받는 것이며 방해되는 기능을 OFF 해주어야 합니다.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//세션을 생성하지 않으며, SecurityContext 정보를 얻기 위해 결코 세션을 사용하지 않습니다.
                .and()
                .formLogin().disable() //4. CSR 방식에서 주로 사용하는 JSON 포맷으로 username과 password를 전송하는 방식을 사용할 것이라 formLogin을 비활성화 한다.
                .httpBasic().disable() //5. username, password 정보를 http header에 실어서 인증을 하는 방식입니다. 우리 프로젝트에서는 사용하지 않을 것이여서 비활성 합니다.
                .exceptionHandling() //예외 처리 설정 시작
                .authenticationEntryPoint(new MemberAuthenticationEntryPoint()) //인증 예외 처리 401 에러
                .accessDeniedHandler(new MemberAccessDeniedHandler()) //권한 예외 처리 403 에러
                .and()
                .apply(new CustomFilterConfigurer()) //사용자 정의 필터 적용
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        //회원 등록의 경우, 접근 권한 여부와 상관없이 누구나 접근이 가능해야 합니다.
                        .antMatchers(HttpMethod.POST, "/*/member").permitAll()
                        //회원 정보 수정의 경우, 일반 사용자만 접근이 가능하도록 허용합니다. **는 하위 URL로 어떤 URL이 오더라도 매치가 된다는 의미입니다.
                        .antMatchers(HttpMethod.PATCH, "/*/members/**").hasRole("USER")
                        //모든 회원 정보의 목록은 관리자권한을 가진 사용자만 접근이 가능합니다.
                        .antMatchers(HttpMethod.GET, "/*/members").hasAnyRole("ADMIN")
                        //특정 회원에 대한 정보 조회는 일반 사용자와 관리자 권한을 가진 사용자 모두 접근이 가능하면 될 것 같습니다.
                        .antMatchers(HttpMethod.GET, "/*/members/**").hasAnyRole("USER", "ADMIN")
                        //특정 회원을 삭제하는 요청은 사용자가 탈퇴 같은 처리를 할 수 있어야 하므로 일반사용자 권한만 가진 사용자만 접근이 가능하도록 허용합니다.

                        .antMatchers(HttpMethod.DELETE, "/*/members/**").hasAnyRole("USER")

                        // 6. jwt를 적용하기 전이므로 우선은 모든 http request 요청에 대해서 접근을 허용하도록 설정했습니다.
                        .anyRequest().permitAll()   //서버 측으로 들어오는 모든 request에 대해서 접근을 허용하고 있다.

                );

        return http.build();

    }

    @Bean
    public PasswordEncoder passwordEncoder() { //7. password Encoder Bean 객체를 생성합니다.
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() { //8. 구체적인 CORS 정책을 설정합니다.
        CorsConfiguration configuration = new CorsConfiguration();

        // 9. 모든 출처(Origin)에 대해 스크립트 기반의 http 통신을 허용하도록 설정
        // 이 설정은 운영 서버 환경에서 요구사항에 맞게 변경이 가능합니다.
        configuration.setAllowedOrigins(Arrays.asList("*"));

        //10. 이 메서드를 통해 파라미터로 지정한 http 메서드에 대한 http 통신을 허용합니다.
        configuration.setAllowedMethods(List.of("GET", "POST", "PATCH", "DELETE"));

        //11. CorsConfigurationSource 인터페이스의 구현 클래스인  source 클래스의 객체를 생성합니다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        //12. 모든 url에 앞에서 구성한 cors 정책(corsConfiguration)을 적용합니다.
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    //Spring Security의 보안 설정 확장
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {
        //configure(HttpSecurity builder) 메서드는 보안 필터를 설정하는 메서드입니다.
        //httpSecurity 객체를 이용하여 인증 및 필터 체인을 구성합니다.
        //httpSecurity 에서 AuthenticationManager를 가져와서 필터에서 사용할 수 있도록 합니다.
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            //AuthenticationManager 사용자의 인증을 관리하는 객체입니다.
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            //로그인 요청을 처리하는 JWT 기반 인증 필터입니다.
            //생성자로 authenticationManger 와 jwtTokenizer (JWT 토큰을 다루는 유틸 클래스)를 주입받습니다.
            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login"); //로그인 요청 url을 /v11/auth/login 으로 설정합니다.

            //사용자가 로그인에 성공하면 JWT 토큰을 생성해서 클라이언트에 반환할 수도 있습니다.
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new MemberAuthenticationSuccessHandler()); //로그인 성공 시 실행할 핸들러 설정
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new MemberAuthenticationFailureHandler()); //로그인 실패 시 실행할 핸들러 설정

            //filter의 인스턴스를 생성하면서 JwtVerificationFilter에서 사용되는 객체들을 생성자로 DI 해줍니다.
            //요청 헤더의 JWT 토큰을 검증하는 필터입니다. jwtTokenizer (JWT 파싱 & 검증)와 authorityUtils (사용자 권한 관리 도구)를 생성자로 주입받습니다.
            JwtVerificaitonFilter jwtVerificaitonFilter = new JwtVerificaitonFilter(jwtTokenizer, authorityUtils);

            //VerificationFilter는 AuthenticationFilter에서 로그인 인증에 성공한 후 발급받은 JWT 클라이언트의
            //request header(Authorizaiton 헤더)에 포함되어 있을 경우에만 동작합니다.
            builder
                    .addFilter(jwtAuthenticationFilter) //로그인 필터를 추가합니다. 로그인 요청 시 동작하는 jwt 인증 필터 추가
                    .addFilterAfter(jwtVerificaitonFilter, JwtAuthenticationFilter.class); //jwt 검증 필터를 추가합니다. 로그인 후 발급된 JWT를 검증하는 JWT 검증 필터 추가

        }
    }


}
