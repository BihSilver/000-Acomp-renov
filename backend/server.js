const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cors());

// Conexão com o MySQL
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'Jeferson0107#', // Sua senha do MySQL
  database: 'sistema_renovacoes',
  waitForConnections: true,
  connectionLimit: 10
});

// ========================================================
// 1. ROTA DE LOGIN
// ========================================================
app.post('/login', async (req, res) => {
  const { matricula, senha } = req.body;

  if (!matricula || !senha) {
    return res.status(400).json({ mensagem: 'Matrícula e senha são obrigatórias.' });
  }

  try {
    const [usuarios] = await pool.query(
      'SELECT * FROM usuarios WHERE matricula = ?',
      [matricula.trim().toUpperCase()]
    );

    if (usuarios.length === 0) {
      return res.status(401).json({ mensagem: 'Matrícula ou senha incorretas.' });
    }

    const usuario = usuarios[0];

    // Verifica se o usuário já criou uma senha
    if (!usuario.senha_hash) {
      return res.status(400).json({ 
        mensagem: 'Usuário ainda não possui senha cadastrada. Faça o Primeiro Acesso.' 
      });
    }

    // Compara a senha informada com o hash salvo no banco
    const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
    if (!senhaValida) {
      return res.status(401).json({ mensagem: 'Matrícula ou senha incorretas.' });
    }

    // Retorna os dados do usuário logado (sem a senha)
    res.json({
      sucesso: true,
      usuario: {
        matricula: usuario.matricula,
        nome: usuario.nome,
        email: usuario.email,
        cargo: usuario.cargo,
        lotacao: usuario.lotacao,
        polo: usuario.polo,
        perfil_acesso: usuario.perfil_acesso
      }
    });
  } catch (erro) {
    console.error('Erro no login:', erro);
    res.status(500).json({ mensagem: 'Erro interno no servidor.' });
  }
});

// ========================================================
// 2. ROTA DE PRIMEIRA DEFINIÇÃO DE SENHA (CADASTRO)
// Confirmando matrícula e nome cadastrado previamente no banco
// ========================================================
app.post('/cadastrar-senha', async (req, res) => {
  const { matricula, nome, novaSenha } = req.body;

  if (!matricula || !nome || !novaSenha) {
    return res.status(400).json({ mensagem: 'Preencha todos os campos obrigatórios.' });
  }

  try {
    // 1. Busca o usuário cadastrado no banco pela matrícula
    const [usuarios] = await pool.query(
      'SELECT * FROM usuarios WHERE matricula = ?',
      [matricula.trim().toUpperCase()]
    );

    if (usuarios.length === 0) {
      return res.status(404).json({ mensagem: 'Matrícula não encontrada no sistema.' });
    }

    const usuario = usuarios[0];

    // 2. Confirma se o nome digitado confere com o nome do banco
    if (!usuario.nome.toUpperCase().includes(nome.trim().toUpperCase())) {
      return res.status(400).json({ mensagem: 'O nome informado não corresponde à matrícula.' });
    }

    // 3. Criptografa a senha e atualiza no banco
    const salt = await bcrypt.genSalt(10);
    const senhaHash = await bcrypt.hash(novaSenha, salt);

    await pool.query(
      'UPDATE usuarios SET senha_hash = ?, status_cadastro = "ativo" WHERE matricula = ?',
      [senhaHash, usuario.matricula]
    );

    res.json({ sucesso: true, mensagem: 'Senha cadastrada com sucesso! Agora você já pode fazer login.' });
  } catch (erro) {
    console.error('Erro ao cadastrar senha:', erro);
    res.status(500).json({ mensagem: 'Erro interno no servidor.' });
  }
});

// ========================================================
// 3. ROTA DE ESQUECI A SENHA (REDEFINIÇÃO)
// Confirmando matrícula e e-mail cadastrado
// ========================================================
app.post('/esqueci-senha', async (req, res) => {
  const { matricula, email, novaSenha } = req.body;

  if (!matricula || !email || !novaSenha) {
    return res.status(400).json({ mensagem: 'Preencha todos os campos obrigatórios.' });
  }

  try {
    const [usuarios] = await pool.query(
      'SELECT * FROM usuarios WHERE matricula = ? AND email = ?',
      [matricula.trim().toUpperCase(), email.trim().toLowerCase()]
    );

    if (usuarios.length === 0) {
      return res.status(404).json({ mensagem: 'Combinação de matrícula e e-mail não encontrada.' });
    }

    const salt = await bcrypt.genSalt(10);
    const senhaHash = await bcrypt.hash(novaSenha, salt);

    await pool.query(
      'UPDATE usuarios SET senha_hash = ? WHERE matricula = ?',
      [senhaHash, matricula.trim().toUpperCase()]
    );

    res.json({ sucesso: true, mensagem: 'Senha redefinida com sucesso!' });
  } catch (erro) {
    console.error('Erro na redefinição de senha:', erro);
    res.status(500).json({ mensagem: 'Erro interno no servidor.' });
  }
});

app.listen(3000, () => {
  console.log('🚀 Back-end rodando em http://localhost:3000');
});