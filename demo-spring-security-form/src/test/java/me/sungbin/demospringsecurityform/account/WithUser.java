package me.sungbin.demospringsecurityform.account;

import org.springframework.security.test.context.support.WithMockUser;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * packageName : me.sungbin.demospringsecurityform.account
 * fileName : WithUser
 * author : rovert
 * date : 2022/02/17
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/17       rovert         최초 생성
 */

@Retention(RetentionPolicy.RUNTIME)
@WithMockUser(username = "sungbin", roles = "USER")
public @interface WithUser {
}
