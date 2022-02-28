package me.sungbin.demospringsecurityform.config;

import lombok.RequiredArgsConstructor;
import me.sungbin.demospringsecurityform.account.AccessDeniedExceptionHandler;
import me.sungbin.demospringsecurityform.account.AccountService;
import me.sungbin.demospringsecurityform.common.LoggingFilter;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import java.util.List;

/**
 * packageName : me.sungbin.demospringsecurityform.config
 * fileName : SecurityConfig
 * author : rovert
 * date : 2022/02/17
 * description :
 * ===========================================================
 * DATE 			AUTHOR			 NOTE
 * -----------------------------------------------------------
 * 2022/02/17       rovert         최초 생성
 */

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final AccessDeniedExceptionHandler accessDeniedExceptionHandler;

    private final AccountService accountService;

    public AccessDecisionManager accessDecisionManager() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
        webExpressionVoter.setExpressionHandler(handler);

        List<AccessDecisionVoter<? extends  Object>> voters = List.of(webExpressionVoter);

        return new AffirmativeBased(voters);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(new LoggingFilter(), WebAsyncManagerIntegrationFilter.class)
                .authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("/user").hasRole("USER")
                .anyRequest().authenticated()
                .accessDecisionManager(accessDecisionManager())
                .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .and()
                .logout().logoutSuccessUrl("/")
                .and()
                .rememberMe()
                .userDetailsService(accountService)
                .key("remember-me-sample")
                .and()
                .httpBasic()
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedExceptionHandler);

        // TODO: ExceptionTranslationFilter -> FilterSecurityInterceptor (AccessDecisionManager, AffirmativeBased)
        // TODO: AuthenticationException -> AuthenticationEntryPoint
        // TODO: AccessDeniedException -> AccessDeniedHandler

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    // best solution
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
}
