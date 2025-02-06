package com.springboot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfiguration {

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
                .formLogin().disable() //4. CSR 방식에서 주로 사용하는 JSON 포맷으로 username과 password를 전송하는 방식을 사용할 것이라 formLogin을 비활성화 한다.
                .httpBasic().disable() //5. username, password 정보를 http header에 실어서 인증을 하는 방식입니다. 우리 프로젝트에서는 사용하지 않을 것이여서 비활성 합니다.

                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll() // 6. jwt를 적용하기 전이므로 우선은 모든 http request 요청에 대해서 접근을 허용하도록 설정했습니다.
                );

        return http.build();

    }

    @Bean
    public PasswordEncoder passwordEncoder () { //7. password Encoder Bean 객체를 생성합니다.
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() { //8. 구체적인 CORS 정책을 설정합니다.
        CorsConfiguration configuration = new CorsConfiguration();

        // 9. 모든 출처(Origin)에 대해 스크립트 기반의 http 통신을 허용하도록 설정
        // 이 설정은 운영 서버 환경에서 요구사항에 맞게 변경이 가능합니다.
        configuration.setAllowedOrigins(Arrays.asList("*"));

        //10. 이 메서드를 통해 파라미터로 지정한 http 메서드에 대한 http 통신을 허용합니다.
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCH", "DELETE"));

        //11. CorsConfigurationSource 인터페이스의 구현 클래스인  source 클래스의 객체를 생성합니다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        //12. 모든 url에 앞에서 구성한 cors 정책(corsConfiguration)을 적용합니다.
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

}
