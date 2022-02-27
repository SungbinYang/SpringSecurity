package me.sungbin.demospringsecurityform.common;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * packageName : me.sungbin.demospringsecurityform.common
 * fileName : SecurityLogger
 * author : rovert
 * date : 2022/02/27
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/27       rovert         최초 생성
 */

@Slf4j
public class SecurityLogger {

    public static void log(String message) {
        log.info(message);
        Thread thread = Thread.currentThread();
        log.info("Thread: " + thread.getName());
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("Principal: " + principal);
    }
}
