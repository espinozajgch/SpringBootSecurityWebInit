package com.web.app.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;

import static com.web.app.security.Constants.*;

@Configuration
@EnableWebSecurity
public class DatabaseWebSecurity extends WebSecurityConfigurerAdapter {

    //@Autowired
    //private DataSource dataSource;

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //configuracion de tablas por defecto
        auth.jdbcAuthentication().dataSource(dataSource)
                //configuracion de tablas personalizada
                .usersByUsernameQuery("select username, password, estatus from Usuarios where username=?")
                .authoritiesByUsernameQuery("select u.username, p.perfil from UsuarioPerfil up " +
                        "inner join Usuarios u on u.id = up.idUsuario " +
                        "inner join Perfiles p on p.id = up.idPerfil " +
                        "where u.username = ?");


    }*/

    /*@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // Los recursos estáticos no requieren autenticación
                .antMatchers(
                        "/bootstrap/**",
                        "/images/**",
                        "/tinymce/**",
                        "/logos/**").permitAll()
                // Las vistas públicas no requieren autenticación
                .antMatchers("/",
                        "/signup",
                        "/search",
                        "/vacantes/view/**").permitAll()
                // Todas las demás URLs de la Aplicación requieren autenticación
                .anyRequest().authenticated()
                // El formulario de Login no requiere autenticacion
                .and().formLogin().permitAll();
    }
    /**/

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        /*
         * 1. Se desactiva el uso de cookies
         * 2. Se activa la configuración CORS con los valores por defecto
         * 3. Se desactiva el filtro CSRF
         * 4. Se indica que el login no requiere autenticación
         * 5. Se indica que el resto de URLs esten securizadas
         */

        httpSecurity
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues()).and()
                .csrf().disable()
                .authorizeRequests().antMatchers(HttpMethod.POST, LOGIN_URL).permitAll()
                .antMatchers(HttpMethod.GET, FILES_URL).permitAll()
                .antMatchers(HttpMethod.GET, "/prueba/**").permitAll()
                .antMatchers(HttpMethod.GET, FUNCIONES_URL).permitAll()
                .antMatchers(HttpMethod.POST, FILES_URL).permitAll()
                .antMatchers(HttpMethod.POST, "/prueba/**").permitAll()
                .antMatchers(HttpMethod.POST, FUNCIONES_URL).permitAll()
                .anyRequest().authenticated().and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .addFilter(new JWTAuthorizationFilter(authenticationManager())
                );

        httpSecurity.headers().contentSecurityPolicy("script-src 'self' report-uri /csp-report-endpoint/").reportOnly();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Se define la clase que recupera los usuarios y el algoritmo para procesar las passwords
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }/**/

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
