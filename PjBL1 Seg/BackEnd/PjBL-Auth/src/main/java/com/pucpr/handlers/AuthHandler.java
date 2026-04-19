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
        if ("OPTIONS".equals(exchange.getRequestMethod())) { /* OPTIONS é usado pelo navegador e serve para verificar permissões (CORS) */
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*"); /* Permite requisições de qualquer origem */
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "*"); /* Permite qualquer header */
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); /* Métodos permitidos */
            exchange.sendResponseHeaders(204, -1); /* 204 = sucesso sem conteúdo, usado para OPTIONS */
            return;
        }
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

        if (!"POST".equals(exchange.getRequestMethod())) { /* Login só pode ser POST, evitando senha na URL */
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        ObjectMapper mapper = new ObjectMapper(); /* Cria conversor entre JSON e Java */
        InputStream is = exchange.getRequestBody(); /* Pega o corpo da requisiçaõ */
        Map<String, String> data = mapper.readValue(is, Map.class); /* Converte JSON em Map */

        String email = data.get("email");
        String senha = data.get("password");

        /* Optional = pode ou não existir */
        Optional<Usuario> userOpt = repository.findByEmail(email);

        /* Segurança contra enumeração (resposta genérica) */
        if (userOpt.isEmpty()) {
            String response = "{\"message\":\"Credenciais inválidas\"}";
            byte[] bytes = response.getBytes("UTF-8");
            exchange.sendResponseHeaders(401, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
            return;
        }

        Usuario user = userOpt.get();

        // BCrypt (compara senha digitada com hash, NÃO diretamente)
        if (!BCrypt.checkpw(senha, user.getSenhaHash())) {
            String response = "{\"message\":\"Credenciais inválidas\"}";
            byte[] bytes = response.getBytes("UTF-8");
            exchange.sendResponseHeaders(401, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
            return;
        }

        /* Cria JWT com dados do usuário */
        String token = jwtService.generateToken(user);

        /* Retorna JSON com token */
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

        // Verificação de email, impede duplicação
        if (repository.findByEmail(email).isPresent()) {
            String response = "{\"message\":\"E-mail já cadastrado\"}";
            byte[] bytes = response.getBytes("UTF-8");
            exchange.sendResponseHeaders(400, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
            return;
        }

        // Hash da senha, gensalt(12) = custo alto (mais seguro), senha nunca é salva em texto
        String hash = BCrypt.hashpw(senha, BCrypt.gensalt(12));

        Usuario user = new Usuario(nome, email, hash, "PACIENTE");

        /* Persistência = grava no JSONA */
        repository.save(user);

        String response = "{\"message\":\"Usuário criado\"}";
        byte[] bytes = response.getBytes("UTF-8");
        exchange.sendResponseHeaders(201, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
