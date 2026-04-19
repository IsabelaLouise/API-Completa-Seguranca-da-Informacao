package com.pucpr.service;
import com.pucpr.model.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtService {

    // TODO: O ALUNO DEVE BUSCAR DE UMA VARIÁVEL DE AMBIENTE (System.getenv)
    // A chave deve ter pelo menos 256 bits (32 caracteres) para o algoritmo HS256.
    private final String SECRET_KEY = System.getenv("JWT_SECRET"); /* pega variável do sistema, evita deixar chave no código */

    private SecretKey getSigningKey() { // Evita que a Secret_Key quebre
        if (SECRET_KEY == null || SECRET_KEY.length() < 32) {
            throw new RuntimeException("JWT_SECRET não definida ou muito curta");
        }
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    /**
     * Gera o token assinado.
     * 1. Define o 'subject' (e-mail do usuário).
     * 2. Adiciona Claims customizadas (como o 'role').
     * 3. Define a data de emissão e expiração (ex: 15 min).
     * 4. Assina com a chave e o algoritmo HS256.
     */
    public String generateToken(Usuario user) {
        // Exemplo de implementação que eles podem seguir ou completar
        String secret = System.getenv("JWT_SECRET"); // Ensinar boas práticas!
        return Jwts.builder()
                .subject(user.getEmail()) // Identifica o usuário
                .claim("role", user.getRole()) // Adiciona permissão
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900000)) // Expira em 15 min
                .signWith(Keys.hmacShaKeyFor(secret.getBytes())) // Assina com chave secreta
                .compact(); // Gera string final do token
    }

    /**
     * Extrai o e-mail (subject) do token.
     * TODO: O ALUNO DEVE IMPLEMENTAR:
     * 1. Usar Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).
     * 2. Retornar o Subject do Payload.
     */
    public String extractEmail(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey()) // Valida assinatura
                .build()
                .parseSignedClaims(token) //Lê o token
                .getPayload()
                .getSubject(); // Pega o email (subject)
    }

    /**
     * Valida se o token é autêntico e não expirou.
     * TODO: O ALUNO DEVE IMPLEMENTAR:
     * 1. Tentar fazer o parse do token.
     * 2. Se o parse falhar (assinatura errada ou expirado), a biblioteca joga uma Exception.
     * 3. Retornar true se o token for válido e false caso capture uma exceção.
     */
    public boolean validateToken(String token) {
        // Verifica assinatura e qualquer erro retorna falso
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey()) //  Verifica assinatura
                    .build()
                    .parseSignedClaims(token);

            return true;
        } catch (Exception e) {
            return false;
        }
    }

}

