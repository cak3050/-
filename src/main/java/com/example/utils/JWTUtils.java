package com.example.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.micrometer.observation.Observation;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.xml.crypto.Data;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Component
public class JWTUtils {
    @Value("${spring.security.jwt.key}")
    String key;
    @Value("${spring.security.jwt.expire}")
    int expire;
    @Resource
    StringRedisTemplate template;
    public boolean invalidateJwt(String headerToken){
        String token=this.convertToken(headerToken);
        if(token ==null)return false;
        Algorithm algorithm=Algorithm.HMAC256(key);
        JWTVerifier jwtVerifier=JWT.require(algorithm).build();
        try{
            DecodedJWT jwt=jwtVerifier.verify(token);
            String id=jwt.getId();
            return deleteToken(id,jwt.getExpiresAt());
        }catch(JWTVerificationException e ){//verify运行时异常
            return false;
        }
    }
    public Integer toId(DecodedJWT jwt) {
        Map<String, Claim> claims = jwt.getClaims();
        return claims.get("id").asInt();
    }
    public DecodedJWT resolveJwt(String headerToken){    //解析jwt令牌
        String token=this.convertToken(headerToken);
        if(token ==null)return null;
        Algorithm algorithm=Algorithm.HMAC256(key);//通过算法和密钥创建一个算法对象用于之后的验证
        JWTVerifier jwtVerifier=JWT.require(algorithm).build();//构造JWt令牌验证方法的对象（.build表示该对象已经构造完毕可以使用）
        try {
            DecodedJWT verify =jwtVerifier.verify(token);//判断JWt令牌是否有效，即是否被篡改过
            if(this.isInvalidToken(verify.getId()))//判断该JWt是否为空
                return null;
            Date expiresAt =verify.getExpiresAt();//.getExpiresAt()返回过期时间
            return new Date().after(expiresAt) ? null :verify;//比较过期时间过期返回空否则 返回一个经过验证的JWt对象
        }catch (JWTVerificationException e ){//verify运行时异常
            return null;
        }
    }
   private boolean deleteToken(String uuid,Date time){
        if(this.isInvalidToken(uuid))
            return false;
        Date now=new Date();
        long expire=Math.max(time.getTime()-now.getTime(),0);
        template.opsForValue()
                .set(Const.JWT_BLACK_LIST+uuid,"",expire, TimeUnit.MICROSECONDS);//以key-value的形式
          return true;                                                                     //将uuid存入Redis中

    }
    private boolean isInvalidToken(String uuid){//判断令牌是否失效
         return Boolean.TRUE.equals(template.hasKey(Const.JWT_BLACK_LIST + uuid));
    }

    public String createJwt(UserDetails details,int id,String username){
        Algorithm algorithm=Algorithm.HMAC256(key);
        Date expire=this.expireTime();
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("id",id)
                .withClaim("name",username)
                .withClaim("authorities",details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(expire)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }
    public UserDetails toUser (DecodedJWT jwt){
        Map<String, Claim> claims=jwt.getClaims();//通过该方法读取JWt令牌中声明（claim）的信息并存储在map中
        return User.withUsername(claims.get("name").asString())//获取name的值并通过.asString()将其转换为字符类型并将其设置为用户名
                .password(("******"))//设置用户密码
                .authorities(claims.get("authorities").asArray(String.class))//设置请求头
                .build();
    }

    public Date expireTime(){
        Calendar calendar=Calendar.getInstance();
        calendar.add(Calendar.HOUR,expire*24);
        return calendar.getTime();
    }
    private String convertToken(String headerToken){
        if(headerToken==null||!headerToken.startsWith("Bearer"))//判读是否为空或者且开头是否为Bearer，若不为则直接返回空
            return null;
        return headerToken.substring(7);//从第七个开始读取
    }

}
