package com.jeiyuen.springsecurity.config;

import javax.sql.DataSource;

import com.jeiyuen.springsecurity.jwt.AuthEntryPointJwt;
import com.jeiyuen.springsecurity.jwt.AuthTokenFilter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    DataSource dataSource;
    private AuthEntryPointJwt unauthorizedHandler;

    @Autowired
    public SecurityConfig(DataSource dataSource, AuthEntryPointJwt unauthorizedHandler) {
        this.dataSource = dataSource;
        this.unauthorizedHandler = unauthorizedHandler;
    }

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(){
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // Setups the security config to have any request be authenticated
        http.authorizeHttpRequests((requests) -> requests
                // Custom authorization (Permit role/all based on url)
                .requestMatchers("/signin").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                .anyRequest()
                .authenticated());
        // Make the API Stateless
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // Setups the security config to have a basic authentication
        // Passes default security configuration (login with predefined credentials/defined credentials on app.props)
        // http.httpBasic(withDefaults());

        // Use created authEntryPointJwt to handle unauthorized exception
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        // Allow iframes to be displayed but only with the same origin
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
        // Disable cross-site request forgery protection
        http.csrf(csrf -> csrf.disable());

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        // Builds the HTTP Security config and returns the bean as a SecurityFilterChain type
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withUsername("user1").password(passwordEncoder().encode("demo123")).roles("USER").build();
        UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("demo123")).roles("ADMIN").build();
        // Uses JDBC to authenticate users
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        // create user temporarily
        jdbcUserDetailsManager.createUser(user1);
        jdbcUserDetailsManager.createUser(admin);
        return jdbcUserDetailsManager;
        // return new InMemoryUserDetailsManager(user1, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
