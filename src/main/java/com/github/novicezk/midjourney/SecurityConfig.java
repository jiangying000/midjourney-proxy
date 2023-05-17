package com.github.novicezk.midjourney;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder)
                .withUser("leo")
                .password(passwordEncoder.encode("leoPass"))
                .roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/mj/**")
                .authenticated()
                .and()
                .csrf()
                .disable()
                .httpBasic();
    }
}
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication();
////                .passwordEncoder(org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance())
////                .withUser("leo")
////                .password(new BCryptPasswordEncoder().encode("leoPass"))
////                .password("{noop}leoPass")
////                .roles("USER");
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/mj/**")
//                .authenticated()
//                .and()
//                .httpBasic().and().csrf().disable();
//    }
//}


//@Configuration
//@EnableWebSecurity
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        auth.inMemoryAuthentication()
//                .withUser("leo")
//                .password(encoder.encode("leoPass"))
//                .roles("USER");
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/mj/**")
//                .authenticated()
//                .and()
//                .httpBasic();
//    }
//}

//@Configuration
//@EnableWebSecurity
//public class CustomWebSecurityConfigurerAdapter {
//
//
//    @Autowire
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//        auth
//                .inMemoryAuthentication()
//                .withUser("user1")
//                .password(passwordEncoder().encode("user1Pass"))
//                .authorities("ROLE_USER");
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/securityNone")
//                .permitAll()
//                .anyRequest()
//                .authenticated()
//                .and()
//                .httpBasic();
////                .authenticationEntryPoint(authenticationEntryPoint);
////        http.addFilterAfter(new CustomFilter(), BasicAuthenticationFilter.class);
////        http.addFilter(BasicAuthenticationFilter.class);
////        return http.build();
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//}
//

//@Configuration
//@EnableWebSecurity
//public class SecurityConfig
//{
////    @Autowired
////    private AppBasicAuthenticationEntryPoint authenticationEntryPoint;
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/mj/**")
////                .permitAll()
////                .anyRequest()
//                .authenticated()
//                .and()
//                .httpBasic().and().csrf().disable();
////        http.authorizeRequests().antMatchers().authenticated()
////                .authenticationEntryPoint(authenticationEntryPoint);
//        return http.build();
//    }
//
//    @Bean
////    public InMemoryUserDetailsManager userDetailsService() {
//    public InMemoryUserDetailsManager userDetailsService() {
//        UserDetails user = User
//                .withUsername("leo")
//                .password(passwordEncoder().encode("leoPass"))
//                .roles("USER_ROLE")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder(8);
//    }
//}
//
//

