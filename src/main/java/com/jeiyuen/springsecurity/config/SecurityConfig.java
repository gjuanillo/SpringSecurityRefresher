package com.jeiyuen.springsecurity.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // Setups the security config to have any request be authenticated
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        // Setups the security config to have a basic authentication
        // Passes default security configuration (login with predefined credentials/defined credentials on app.props)
        http.httpBasic(withDefaults());
        // Builds the HTTP Security config and returns the bean as a SecurityFilterChain type
        return http.build();
    }
}
