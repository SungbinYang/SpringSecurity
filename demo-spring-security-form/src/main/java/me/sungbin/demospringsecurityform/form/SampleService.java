package me.sungbin.demospringsecurityform.form;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;

/**
 * packageName : me.sungbin.demospringsecurityform.form
 * fileName : SampleService
 * author : rovert
 * date : 2022/02/20
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/20       rovert         최초 생성
 */

@Service
public class SampleService {

    public void dashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal(); // 사용자 정보
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();// 사용자의 권한 정보
        Object credentials = authentication.getCredentials();
        boolean authenticated = authentication.isAuthenticated();
    }
}
