package me.sungbin.demospringsecurityform.common;

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

public class SecurityLogger {

    public static void log(String message) {
        System.out.println(message);
        Thread thread = Thread.currentThread();
        System.out.println("Thread: " + thread.getName());
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        System.out.println("Principal: " + principal);
    }
}
