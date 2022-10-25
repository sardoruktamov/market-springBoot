package uz.market.backend.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class JwtTokenFilter extends GenericFilterBean {
    // klent tomonidan kelayotgan va ketayotgan barcha malumot birinchi bolib doFilterga keladi

    private final JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        // klent tomonidan kelayotgan barcha sorovlarni ushlab olish
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        //kelayotgan Datani ichidan tokenni olamiz
        String jwt = resolveToket(httpServletRequest);
        if (StringUtils.hasText(jwt) && this.jwtTokenProvider.validateToken(jwt)){
            Authentication authentication = this.jwtTokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request,response);
    }

    private String resolveToket(HttpServletRequest httpServletRequest) {
        //headerni ushlab olib tokenni headersga solib jonatamiz
        String bearerToken = httpServletRequest.getHeader("Authorization");
        //olingan tokenni Null va boshqa holatlarga tekshirib koramiz
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
            // bearertokenni 7(Bearer ) ta belgisini kesib qolganini yuboramiz
            return bearerToken.substring(7);
        }
        return null;
    }
}