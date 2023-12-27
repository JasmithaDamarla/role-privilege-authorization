package com.authorize.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.authorize.service.implementation.CustomUserDetailsService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration	
public class SecurityConfig {
	
	
	protected static final String[] PUBLIC_PATHS = {
            "/v3/api-docs.yaml",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/login",
            "/auth/token",
            "/auth/validate",
            "/users/**",
            "/api/fields"
    };
	
    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        log.info("auth config");
        return httpSecurity
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers(PUBLIC_PATHS).permitAll()
//                    .requestMatchers(HttpMethod.GET,"/api/orgs/**").hasAuthority("READ_PRIVILEGE")
//                    .requestMatchers(HttpMethod.POST,"/api/orgs").hasAuthority("CREATE_PRIVILEGE")
//                    .requestMatchers(HttpMethod.PUT,"/api/orgs").hasAuthority("UPDATE_PRIVILEGE")
//                    .requestMatchers(HttpMethod.DELETE,"/api/orgs").hasAuthority("DELETE_PRIVILEGE")
                    .anyRequest()
                    .authenticated()
                )
                .httpBasic(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
    	log.info("authentication provider");
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    	log.info("authentication configuration");
        return config.getAuthenticationManager();
    }
}