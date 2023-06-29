/**
 * This is just to learn the different flow of security. DON'T use it directly on PROD
 * And for simplicity purpose, I have written everything in one file...
 */

package dev.sk.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;

@SpringBootApplication
public class SpringSecurityInmemoryUserdetailsManagerApplication {

	@Configuration
//    @EnableWebSecurity(debug = true)
	@EnableWebSecurity
	static class SecurityConfig{

//        @Autowired
//        MyFilter myFilter;

		@Autowired
		CustomAuth customAuth;
		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity)throws Exception{
			httpSecurity.authorizeRequests(x->x.anyRequest().authenticated());
			httpSecurity.formLogin(Customizer.withDefaults());
//            httpSecurity.addFilterAfter(myFilter, BasicAuthenticationFilter.class);
			return httpSecurity.build();
		}
		@Bean
		public AuthenticationManager test(HttpSecurity httpSecurity)throws Exception{
			AuthenticationManagerBuilder authenticationManagerBuilder =
					httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
			authenticationManagerBuilder.authenticationProvider(customAuth);
			return authenticationManagerBuilder.build();
		}
	}

	@Configuration
	static  class ProjectConfig{

		String tmp_username = "admin";
		String tmp_password = "12345";
		@Bean
		public PasswordEncoder passwordEncoder(){
			return PasswordEncoderFactories.createDelegatingPasswordEncoder();
		}
		@Bean
		public UserDetailsService userDetailsService(){
			UserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
			userDetailsManager.createUser(
					User.withUsername(tmp_username).password(bcryptEncode(tmp_password)).build()
			);
			return userDetailsManager;
		}

		private String bcryptEncode(final String passwd){
			return "{bcrypt}"+ new BCryptPasswordEncoder().encode(passwd);
		}

	}
	@Configuration
	static class CustomAuth implements AuthenticationProvider{

		@Autowired
		UserDetailsService userDetailsService;
		@Autowired
		PasswordEncoder passwordEncoder;

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			String uname = authentication.getName();
			try{
				//In case, User not found it'll raise Exception
				UserDetails userDetails = userDetailsService.loadUserByUsername(uname);

				if (!passwordEncoder.matches(authentication.getCredentials().toString(), userDetails.getPassword())){
					throw new BadCredentialsException("");
				}
				return new UsernamePasswordAuthenticationToken(uname,authentication.getCredentials().toString(), List.of());

			}catch (Exception exception){
				System.err.println("Invalid Username/Password");
				throw new BadCredentialsException("Invalid Username/Password");
			}
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
		}
	}

	@RestController
	static class MyController{
		@RequestMapping("/")
		public String main(){
			return "Hello Spring Security...";
		}
	}

    /*@Component
    class MyFilter implements Filter{
        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
            filterChain.doFilter(servletRequest,servletResponse);
        }
    }*/

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityInmemoryUserdetailsManagerApplication.class, args);
	}

}
