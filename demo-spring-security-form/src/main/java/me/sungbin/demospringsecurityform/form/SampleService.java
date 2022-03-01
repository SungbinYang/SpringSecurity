package me.sungbin.demospringsecurityform.form;

import lombok.extern.slf4j.Slf4j;
import me.sungbin.demospringsecurityform.common.SecurityLogger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.annotation.security.RolesAllowed;

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

    @Secured("ROLE_USER")
    public void dashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails principal = (UserDetails) authentication.getPrincipal();
        log.info("===================================");
        log.info(authentication.toString());
        log.info(principal.getUsername());
    }

    @Async
    public void asyncService() {
        SecurityLogger.log("Async Service");
        log.info("Async service is called");
    }
}
