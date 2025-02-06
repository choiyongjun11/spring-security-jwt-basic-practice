package com.springboot.auth;

import com.springboot.exception.BusinessLogicException;
import com.springboot.exception.ExceptionCode;
import com.springboot.member.entity.Member;
import com.springboot.member.repository.MemberRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;


/*
JWT 자격 증명을 위한 로그인 인증 구현
사용자의 Usernmae(이메일 주소)와 Password로 로그인 인증에 성공하면 로그인 인증에 성공한 사용자에게 JWT 를 생성 및 발급 하는 것입니다.

JWT 흐름 과정
1. 클라이언트가 서버 측에 로그인 인증 요청(Username/Password) 를 서버 측에 전송합니다.
2. 로그인 인증을 담당하는 Security Filter (JwtAuthenticationFilter)가 클라이언트의 로그인 인증 정보 수신
3. Security Filter가 수신한 로그인 인증 정보를 AuthenticationManger 에게 전달해 인증 처리를 위임합니다.
4. AuthenticationManger 가 UserDetailsService (MemberDetailsService)에게 사용자의 UserDetails 조회를 위임합니다.
5. UserDetailsService(MemberDetailsService)가 사용자의 크리덴셜을 DB에서 조회한 후, AuthenticationManger에게 사용자의 UserDetails 를 전달합니다.
6. AuthenticationManager 가 로그인 인증 정보와 UserDetails의 정보를 비교해 인증 처리합니다.
7. JWT 생성 후, 클라이언트의 응답으로 전달합니다.

따라서, 우리는 JwtAuthenticationFilter, MemberDetailsService를 구현해야 합니다.
AuthenticationManger 는 spring security가 대신 처리해주기 때문에 신경 쓸 필요가 없습니다.

*/

/*
구현 과제) - UserDetailsService 구현
 Spring Security에서 사용자의 로그인 인증을 처리하는 가장 단순하고 효과적인 방법은 데이터베이스에서 사용자의 크리덴셜을 조회한 후,
 조회한 크리덴셜을 AuthenticationManager에게 전달하는 UserDetailsService를 구현하는 것입니다.
 Spring Security에서 제공하는 UserDetailsService 인터페이스를 구현하여 사용자 정보를 관리하는 MemberDetailsService 클래스를 작성합니다.

 */

@Component
public class MemberDetailsService implements UserDetailsService {

    //1. 회원 정보를 조회할 수 있는 기능, 회원의 권한 정보를 조회 할 수 있는 기능이 필요합니다.
    private final MemberRepository memberRepository; //1.1 회원 정보를 데이터베이스에서 조회하는 레포지토리를 주입합니다.
    private final AuthorityUtils authorityUtils; // 1.2 회원의 권한 정보를 처리하는 유틸도 주입을 해줍니다.


    public MemberDetailsService(MemberRepository memberRepository, AuthorityUtils authorityUtils) {
        this.memberRepository = memberRepository; // 1.3 의존성 주입을 통해 회원 정보를 관리합니다.
        this.authorityUtils = authorityUtils; // 1.4 의존성 주입을 통해 권한 관련 유틸리티를 사용합니다.
    }

    /*
 2. UserDetailsService 미리 구현된 인터페이스를 가져오고 난 뒤 메서드를 우리가 사용하고 싶은 양식에 맞도록 재정의를 해야 합니다.
    UserDetailsService 인터페이스에 마우스를 대고 ctrl + 마우스 왼쪽 클릭하여 양식을 가져옵니다. 양식은 다음과 같습니다.

    public interface UserDetailsService {
        UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
    }

    2.1 이 문장을 가지고 우리가 원하는 기능으로 재구성해야 하며, 새로운 UserDetails 로 재정의 해야합니다.

    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    }

     */

    @Override //메서드를 재정의 합니다.
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<Member> optionalMember = memberRepository.findByEmail(username);
        Member findMember = optionalMember.orElseThrow( () ->
                new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND));


        return new MemberDetails(findMember);

    }
}
