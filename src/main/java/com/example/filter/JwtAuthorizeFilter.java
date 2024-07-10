package com.example.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.config.SecurityConfiguration;
import com.example.utils.JWTUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
public class JwtAuthorizeFilter extends OncePerRequestFilter {
    @Resource//自动装配
    JWTUtils utils;//导入写好的JWt工具类
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorization =request.getHeader("Authorization");//从请求头中读取JWt
        DecodedJWT jwt=utils.resolveJwt(authorization);//解析获取到的JWt
        if(jwt!=null){
            UserDetails user=utils.toUser(jwt);
            UsernamePasswordAuthenticationToken authentication=
                    new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);//这段代码创建了一个UsernamePasswordAuthenticationToken对象，
            // 将用户信息、权限信息添加到该对象中，然后使用setDetails方法添加了关于认证请求的详细信息，
            // 最后将该认证对象存储在SecurityContextHolder的上下文中。
        }
        filterChain.doFilter(request,response);

    }
}
