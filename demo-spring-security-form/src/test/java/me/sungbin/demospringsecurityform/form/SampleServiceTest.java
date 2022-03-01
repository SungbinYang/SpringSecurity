package me.sungbin.demospringsecurityform.form;

import me.sungbin.demospringsecurityform.account.AccountService;
import me.sungbin.demospringsecurityform.account.WithAdmin;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;

/**
 * packageName : me.sungbin.demospringsecurityform.form
 * fileName : SampleServiceTest
 * author : rovert
 * date : 2022/03/01
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/03/01       rovert         최초 생성
 */

@SpringBootTest
class SampleServiceTest {

    @Autowired
    SampleService sampleService;

    @Autowired
    AccountService accountService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Test
    @WithAdmin
    @DisplayName("dashboard() 테스트")
    void dashboard() {
        sampleService.dashboard();
    }
}