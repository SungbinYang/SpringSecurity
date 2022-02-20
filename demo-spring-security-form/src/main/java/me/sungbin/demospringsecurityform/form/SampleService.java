package me.sungbin.demospringsecurityform.form;

import lombok.extern.slf4j.Slf4j;
import me.sungbin.demospringsecurityform.account.Account;
import me.sungbin.demospringsecurityform.account.AccountContext;
import org.springframework.stereotype.Service;

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

@Slf4j
@Service
public class SampleService {

    public void dashboard() {
        Account account = AccountContext.getAccount();
        log.info("===================================");
        log.info(account.getUsername());
    }
}
