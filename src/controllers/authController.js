import UserModel from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

class AuthController {
    // Listar todos os usuários
    async getAllUsers(req, res) {
        try {
            const users = await UserModel.findAll();
            res.json(users);
        } catch (error) {
            console.error("Erro ao listar usuários:", error);
            res.status(500).json({ error: "Erro ao listar usuários" });
        }
    }

    // Registrar um novo usuário
    async register(req, res) {
        try {
            const { name, email, password } = req.body;

            // Validação básica
            if (!name || !email || !password) {
                return res.status(400).json({ error: "Os campos nome, email e senha são obrigatórios" });
            }

            // Verifica se o usuário já existe
            const userExists = await UserModel.findByEmail(email);
            if (userExists) {
                return res.status(400).json({ error: "Este email já está cadastrado" });

            }

            // Hasha da senha
            const hashedPassword = await bcrypt.hash(password, 10);

            // Cria objeto do usuário
            const data = {
                name,
                email,
                password: hashedPassword,
            };

            // Cria o usuário
            const user = await UserModel.create(data);
            return res.status(201).json({
                message: "Usuário criado com sucesso",
                user,
            });
        } catch (error) {
            console.error("Erro ao registrar usuário:", error);
            res.status(500).json({ error: "Erro ao registrar usuário" });

        }
    }

    async login(req, res) {
        try {
            const { email, password } = req.body;

            if (!email || !password) {
                return res.status(400).json({ error: "Os campos email e senha são obrigatórios" });
            }

            // Verifica se o usuário já existe
            const userExist = await UserModel.findByEmail(email);
            if (!userExist) {
                return res.status(401).json({ error: "Credenciais inválidas" });
            }
            // Verificar senha
            const isPasswordValid = await bcrypt.compare(password, userExist.password);
            if (!isPasswordValid) {
                return res.status(401).json({ error: "Credenciais inválidas" });
            }

            // Gerar Token JWT
            const token = jwt.sign(
                { id: userExist.id, 
                name: userExist.name,
                email: userExist.email 
            },
                process.env.JWT_SECRET,
                { 
                    expiresIn: "24h" 
                } // O token expira em 1 hora
            );

            return  res.json({
                message: "Login realizado com sucesso",
                token,
                userExist,
            });
        } catch (error) {
            console.error("Erro ao fazer login:", error);
            res.status(500).json({ error: "Erro ao fazer login" });
        }
    }



}

export default new AuthController();
