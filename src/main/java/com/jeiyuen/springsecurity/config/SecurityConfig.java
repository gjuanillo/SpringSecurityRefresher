package com.jeiyuen.springsecurity.config;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    DataSource dataSource;

    @Autowired
    SecurityConfig(DataSource dataSource){
        this.dataSource = dataSource;
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // Setups the security config to have any request be authenticated
        http.authorizeHttpRequests((requests) -> requests
                // Custom authorization (Permit role/all based on url)
                .requestMatchers("/h2-console/**").permitAll()
                .anyRequest()
                .authenticated());
        // Make the API Stateless
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // Setups the security config to have a basic authentication
        // Passes default security configuration (login with predefined credentials/defined credentials on app.props)
        http.httpBasic(withDefaults());
        // Allow iframes to be displayed but only with the same origin
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
        // Disable cross-site request forgery protection
        http.csrf(csrf -> csrf.disable());
        // Builds the HTTP Security config and returns the bean as a SecurityFilterChain type
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withUsername("user1").password("{noop}demo123").roles("USER").build();
        UserDetails admin = User.withUsername("admin").password("{noop}demo123").roles("ADMIN").build();
        // Uses JDBC to authenticate users
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        // create user temporarily
        jdbcUserDetailsManager.createUser(user1);
        jdbcUserDetailsManager.createUser(admin);
        return jdbcUserDetailsManager;
        // return new InMemoryUserDetailsManager(user1, admin);
    }
}
