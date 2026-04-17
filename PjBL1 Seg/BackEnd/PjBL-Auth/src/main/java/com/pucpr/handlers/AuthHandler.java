package com.pucpr.handlers;

import com.pucpr.repository.UsuarioRepository;
import com.pucpr.service.JwtService;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.mindrot.jbcrypt.BCrypt;
import com.pucpr.model.Usuario;

import java.io.InputStream;
import java.util.Map;
import java.util.Optional;

/**
 * Classe responsável por gerenciar as requisições de Autenticação.
 * Aqui o aluno aprenderá a manipular o corpo de requisições HTTP e
 * aplicar conceitos de hashing e proteção de dados.
 */
public class AuthHandler {
    private final UsuarioRepository repository;
    private final JwtService jwtService;

    public AuthHandler(UsuarioRepository repository, JwtService jwtService) {
        this.repository = repository;
        this.jwtService = jwtService;
    }

    /**
     * Gerencia o processo de Login.
     * Objetivo: Validar credenciais e emitir um passaporte (JWT).
     */
    public void handleLogin(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            exchange.sendResponseHeaders(204, -1);
            return;
        }
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        ObjectMapper mapper = new ObjectMapper();
        InputStream is = exchange.getRequestBody();
        Map<String, String> data = mapper.readValue(is, Map.class);

        String email = data.get("email");
        String senha = data.get("password");

        Optional<Usuario> userOpt = repository.findByEmail(email);

        if (userOpt.isEmpty()) {
            String response = "{\"message\":\"Credenciais inválidas\"}";
            byte[] bytes = response.getBytes("UTF-8");
            exchange.sendResponseHeaders(401, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
            return;
        }

        Usuario user = userOpt.get();

        // BCrypt (ESSENCIAL)
        if (!BCrypt.checkpw(senha, user.getSenhaHash())) {
            String response = "{\"message\":\"Credenciais inválidas\"}";
            byte[] bytes = response.getBytes("UTF-8");
            exchange.sendResponseHeaders(401, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
            return;
        }

        String token = jwtService.generateToken(user);

        String response = "{\"token\":\"" + token + "\"}";

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        byte[] bytes = response.getBytes("UTF-8");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    /**
     * Gerencia o processo de Cadastro (Registro).
     * Objetivo: Criar um novo usuário de forma segura.
     */
    public void handleRegister(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        ObjectMapper mapper = new ObjectMapper();

        InputStream is = exchange.getRequestBody();
        Map<String, String> data = mapper.readValue(is, Map.class);

        String nome = data.get("name");
        String email = data.get("email");
        String senha = data.get("password");

        // Verifica se já existe
        if (repository.findByEmail(email).isPresent()) {
            String response = "{\"message\":\"E-mail já cadastrado\"}";
            byte[] bytes = response.getBytes("UTF-8");
            exchange.sendResponseHeaders(400, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
            return;
        }

        // Hash da senha
        String hash = BCrypt.hashpw(senha, BCrypt.gensalt(12));

        Usuario user = new Usuario(nome, email, hash, "PACIENTE");

        repository.save(user);

        String response = "{\"message\":\"Usuário criado\"}";
        byte[] bytes = response.getBytes("UTF-8");
        exchange.sendResponseHeaders(201, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
