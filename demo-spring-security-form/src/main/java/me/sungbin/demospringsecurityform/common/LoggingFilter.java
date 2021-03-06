package me.sungbin.demospringsecurityform.common;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StopWatch;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * packageName : me.sungbin.demospringsecurityform.common
 * fileName : LoggingFilter
 * author : rovert
 * date : 2022/03/01
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/03/01       rovert         최초 생성
 */

@Slf4j
public class LoggingFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        StopWatch stopWatch = new StopWatch();
        stopWatch.start(((HttpServletRequest) request).getRequestURI());

        chain.doFilter(request, response);

        stopWatch.stop();

        log.info(stopWatch.prettyPrint());
    }
}
