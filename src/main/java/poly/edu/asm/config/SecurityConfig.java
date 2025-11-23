package poly.edu.asm.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityConfig  {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder pe) {
        String password = pe.encode("123");

        UserDetails user1 = User.withUsername("user@gmail.com")
                .password(password)
                .roles("USER")
                .build();

        UserDetails user2 = User.withUsername("admin@gmail.com")
                .password(password)
                .roles("ADMIN")
                .build();

        UserDetails user3 = User.withUsername("both@gmail.com")
                .password(password)
                .roles("USER", "ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user1, user2, user3);
    }

    @Bean
    public org.springframework.security.web.SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Bỏ CSRF và CORS
        http.csrf(csrf -> csrf.disable())
                .cors(cors -> cors.disable());

        // Cho phép truy cập tất cả
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/poly/url1", "/poly/url2").hasRole("USER")
                        .requestMatchers("/poly/url3").hasRole("ADMIN")
                        .requestMatchers("/poly/url4").hasAnyRole("USER", "ADMIN")
//                .requestMatchers("/poly/**").denyAll() // chặn các URL khác trong /poly/
                        .anyRequest().permitAll() // cho phép các URL khác ngoài /poly/
        );

        // Hiện form lỗi khi người dùng không có quyền truy cập
        http.exceptionHandling(denied -> denied.accessDeniedPage("/denied"));

        // Sử dụng form đăng nhập mặc định
        http.formLogin(config -> {
            config.loginPage("/login/form");
            config.loginProcessingUrl("/login/check");
            config.defaultSuccessUrl("/login/success");
            config.failureUrl("/login/failure");
            config.permitAll();
            config.usernameParameter("username");
            config.passwordParameter("password");
        });

        // Ghi nhớ đăng nhập
        http.rememberMe(config -> {
            config.tokenValiditySeconds(3 * 24 * 60 * 60); // 3 ngày
            config.rememberMeCookieName("remember-me");
            config.rememberMeParameter("remember-me");
        });

        // Cho phép đăng xuất
        http.logout(config -> {
            config.logoutUrl("/logout");
            config.logoutSuccessUrl("/login/exit");
            config.clearAuthentication(true);
            config.invalidateHttpSession(true);
            config.deleteCookies("remember-me");
        });

        return http.build();
    }
}
