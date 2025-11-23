package poly.edu.asm.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Stream;

@Service("auth")
public class AuthService {
    public Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public String getUsername() {
        return getAuthentication().getName();
    }

    public List<String> getRoles() {
        return this.getAuthentication().getAuthorities()
                .stream().map(au -> au.getAuthority().substring(5)).toList();
    }
    public boolean isAuthenticated() {
        Authentication auth = getAuthentication();
        return auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName());
    }


    public boolean hasAnyRole(String... rolesToCheck) {
        var grantedRoles = this.getRoles();
        return Stream.of(rolesToCheck).anyMatch(role -> grantedRoles.contains(role));
    }
}
