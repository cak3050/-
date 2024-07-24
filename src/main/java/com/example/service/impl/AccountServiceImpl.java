package com.example.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.entity.vo.request.ConfirmResetVO;
import com.example.entity.vo.request.EmailRegisterVO;
import com.example.entity.vo.request.EmailResetVO;
import com.example.mapper.AccountMapper;
import com.example.service.AccountService;
import com.example.entity.dto.Account;
import com.example.utils.Const;
import com.example.utils.FlowUtils;
import jakarta.annotation.Resource;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account>implements AccountService {
    @Resource
    AmqpTemplate amqpTemplate;
    @Resource
    FlowUtils flowUtils;
    @Resource
    PasswordEncoder encode;
    @Resource
    StringRedisTemplate stringRedisTemplate;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account=this.findAccountByNameOrEmail(username);
        if(account==null)throw new UsernameNotFoundException("用户名或密码错误");
        return User
                .withUsername(username)
                .password(account.getPassword())//@Data里实现自带的方法
                .roles(account.getRole())
                .build();//装成build类
    }
    public Account findAccountByNameOrEmail(String text){//查询用户信息
        return this.query()
                .eq("username",text).or()
                .eq("email",text)//给查询添加条件
                .one();//表示只会返回一个结果，有多个结果则返回第一个
    }

    @Override//获取验证码相关
    public String registerEmailVerifyCode(String type, String email, String ip) {
        synchronized (ip.intern()){//IP锁，防止同时进行多次请求
            if(!this.verifyLimit(ip))
                return "请求频繁，请稍后再试";
            Random random=new Random();
            int code=random.nextInt(900000)+100000;
            Map<String, Object>data= Map.of("type",type,"email",email,"code",code);
            amqpTemplate.convertAndSend("mail",data);
            stringRedisTemplate.opsForValue()
                    .set(Const.VERIFY_EMAIL_DATA + email, String.valueOf(code), 3, TimeUnit.MINUTES);
            return null;
        }
    }

    @Override
    public String registerEmailAccount(EmailRegisterVO info){
        String email = info.getEmail();
        String key=Const.VERIFY_EMAIL_DATA+email;
        String code =  stringRedisTemplate.opsForValue().get(key);
        if (code != null && !code.equals(info.getCode())) return "验证码错误，请重新输入";
        if(this.existsAccountByEmail(email)) return "该邮件地址已被注册";
        String username = info.getUsername();
        if(this.existsAccountByUsername(username)) return "该用户名已被他人使用，请重新更换";
        String password = encode.encode(info.getPassword());
        Account account = new Account(null, info.getUsername(),
                password, email,"user", new Date());
        if(this.save(account)) {
            stringRedisTemplate.delete(key);
            return null;
        } else {
            return "内部错误，注册失败";

        }
    }

    @Override
    public String resetEmailAccountPassword(EmailResetVO vo) {
        String email =vo.getEmail();
        String verify =this.resetConfirm(new ConfirmResetVO(email,vo.getCode()));
        if(verify !=null)return verify;
        String password= encode.encode(vo.getPassword());
        boolean update=this.update().eq("email",email).set("password",password).update();
        if(update){
            stringRedisTemplate.delete(Const.VERIFY_EMAIL_DATA+email);

        }
        return null;
    }


    @Override
    public String resetConfirm(ConfirmResetVO info) {
        String email = info.getEmail();
        String key=Const.VERIFY_EMAIL_DATA+email;
        String code =  stringRedisTemplate.opsForValue().get(key);
        if(code == null) return "请先获取验证码";
        if(!code.equals(info.getCode())) return "验证码错误，请重新输入";
        return null;
    }

    @Override
    public Account findAccountById(int id) {
        return this.query().eq("id",id).one();
    }

    private String getEmailVerifyCode(String email){
        String key = Const.VERIFY_EMAIL_DATA + email;
        return stringRedisTemplate.opsForValue().get(key);
    }
    private boolean existsAccountByEmail(String email){
        return this.baseMapper.exists(Wrappers.<Account>query().eq("email", email));
    }
    private boolean verifyLimit(String ip){
        String key =Const.VERIFY_EMAIL_LIMIT+ip;
        return flowUtils.limitOnceCheck(key,60);
    }
    private boolean existsAccountByUsername(String username){
        return this.baseMapper.exists(Wrappers.<Account>query().eq("username", username));
    }
}
