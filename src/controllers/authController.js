import UserModel from "../models/userModel";
import bcrypt from "bcrypt.js";

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
}

export default new AuthController();
