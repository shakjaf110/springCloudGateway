package com.example.springCloudGateway;


import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory {

    @Value("${demo.app.jwtSecret}")
    String secretKey;

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange,chain)->{
            ServerHttpRequest request = exchange.getRequest();
            if(!request.getHeaders().containsKey("Authorization"))
            {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            String jwt=request.getHeaders().getValuesAsList("Authorization").get(0);
            jwt=jwt.replace("Bearer ","");
            try{
                if (!isJwtValidate(jwt))
                {
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return response.setComplete();
                }
            }catch (Exception e)
            {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            return chain.filter(exchange);
        };
    }

    boolean isJwtValidate(String  token)
    {
        String subject= Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
        if(subject==null || subject.isEmpty())
            return false;
        return true;
    }
}
