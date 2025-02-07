package com.springboot.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

/*
JWT 를 생성하는 JwtTokenizer 구현
JwtTokenizer 클래스는 로그인 인증에 성공한 클라이언트에게 JWT를 생성 및 발급하고 클라이언트의 요청이 들어올 때마다 전달된 JWT를 검증하는 역할을 합니다.

 토큰이란?
 토큰(Token)은 특정 정보를 포함하는 문자열이며, 주로 JWT(Json Web Token) 형식으로 사용됩니다.
 JWT는 JSON 데이터를 안전하게 전송하기 위한 토큰으로, 서명(signature)을 포함하여 데이터의 무결성을 보장합니다.
 토큰은 세션과 다르게 서버의 상태(State)를 저장하지 않고, 클라이언트가 직접 정보를 가지고 다닌다는 점에서 Stateless(무 상태성)을 유지할 수 있습니다.

 JWT (Json web Token) 구조 - Header, Payload, Signature 가 있습니다.
 Header 에는 토큰의 타입(JWT)과 해싱 알고리즘(HMAC, SHA256, RSA 등 기법)이 있습니다.
 Payload 에는 실제 담고 싶은 정보 (사용자 ID, 권한, 만료 시간 등) 있습니다.
 Sigature 에는 해더 + 페이로드를 비밀키 (Secret Key)로 서명한 값 입니다. 이를 통해 토큰이 변조되지 않았음을 검증합니다.

 - Token을 구성할려면 총 3개가 필요합니다. (1. secretKey, 2. accessToken, 3. refreshToken)
 - 토큰(Token)은 인증, 인가 과정에서 중요한 역할을 하는 문자열 입니다.
 - 주로 사용자의 신원 확인과 권한 부여를 위해 사용되며, 서버와 클라이언트 간의 보안성을 높이는데 기여합니다.

 */

@Component
public class JwtTokenizer {
    @Getter
    @Value("${jwt.key}")
    private String secretKey;
    //비밀 키

    @Getter
    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenExpirationMinutes;
    //어센스 토큰 만료 시간

    @Getter
    @Value("${jwt.refresh-token-expiration-minutes}")
    private int refreshTokenExpirationMinutes;
    //리프레쉬 토큰 만료 시간

    //주어진 secretKey를 Base64로 인코딩하여 반환합니다. Base64는 바이너리 데이터를 텍스트로 변환하는 인코딩 방식입니다.
    public String encodeBase64SecretKey(String secretKey) {
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    /*
    JWT(JSON Web Token) 엑세스 토큰을 생성하는 기능을 수행합니다.
    클라이언트가 로그인하면 서버는 이 메서드를 호출하여 사용자의 정보를 담은 토큰을 발급합니다.
    발급된 토큰을 클라이언트가 API 요청 시 인증 헤더에 포함하면, 서버는 이를 검증하여 요청을 처리합니다.

    AccessToken 에는 clamis(사용자 정보), subject(사용자 id, email), expiration(만료 시간), base64인코딩된 비밀 키(서명에 사용)
    을 포함하는 JWT 액세스 토큰을 생성합니다.

     */

    public String generateAccessToken(Map<String, Object> claims,
                                      String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey (base64EncodedSecretKey); //Key 객체로 변환합니다.

        return Jwts.builder()  //jwt 생성기(builder)를 생성합니다.
                .setClaims(claims) //액세스 토큰에는 사용자 정보를 넣어줍니다.
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }

    //리프레쉬 토큰 생성
    public String generateRefreshToken(String subject,
                                       Date expiration,
                                       String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();

    }

    public Jws <Claims> getClaims(String jws, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws);

        return claims;
    }

    public void verifySignature(String jws, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws);
    }

    public Date getTokenExpiration(int expirationMinutes) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, expirationMinutes);
        Date expiration = calendar.getTime();

        return expiration;
    }

    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) {
        byte[]keyBytes = Decoders.BASE64URL.decode(base64EncodedSecretKey);
        Key key = Keys.hmacShaKeyFor(keyBytes);

        return key;
    }

}
