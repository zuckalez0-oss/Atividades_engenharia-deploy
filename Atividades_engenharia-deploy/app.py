import os
import json
import uuid
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_from_directory
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Carrega variáveis de ambiente do arquivo .env para desenvolvimento local
# Em produção (no Render), estas variáveis serão configuradas no painel do serviço.
from dotenv import load_dotenv
load_dotenv()

# --- CONFIGURAÇÃO ---
basedir = os.path.abspath(os.path.dirname(__file__))
# usuarios_json_path = os.path.join(basedir, 'usuarios.json')

app = Flask(__name__)

# --- CONFIGURAÇÕES DE PRODUÇÃO ---
# Lê a SECRET_KEY a partir de uma variável de ambiente. Essencial para segurança.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'uma-chave-secreta-muito-segura-trocar-em-producao')

# Lê a URL do banco de dados a partir de uma variável de ambiente.
# O Render fornecerá uma URL para um banco de dados PostgreSQL.
# Se a variável de ambiente não existir, ele volta para um SQLite local (para facilitar o desenvolvimento).
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///' + os.path.join(basedir, 'atividades.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuração de Upload de Arquivos
UPLOAD_BASE_FOLDER = os.path.join(basedir, 'static', 'uploads')
app.config['UPLOAD_FOLDER_ATIVIDADES'] = os.path.join(UPLOAD_BASE_FOLDER, 'atividades')
app.config['UPLOAD_FOLDER_PEDIDOS'] = os.path.join(UPLOAD_BASE_FOLDER, 'pedidos')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'xlsx', 'txt'}

# Cria as pastas de upload se não existirem
os.makedirs(app.config['UPLOAD_FOLDER_ATIVIDADES'], exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER_PEDIDOS'], exist_ok=True)


db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça o login para acessar esta página."
login_manager.login_message_category = "info"


# --- FUNÇÕES AUXILIARES ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# --- MODELOS DE DADOS ---
class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuarios' # Nome explícito da tabela
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    nome = db.Column(db.String(120), nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Usuario {self.nome}>'

# (Você adicionaria aqui seus outros modelos: Atividade, Pedido, etc.)
# Exemplo:
# class Atividade(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     descricao = db.Column(db.String(500), nullable=False)
#     data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
#     usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


# --- ROTAS ---
@app.route('/')
@login_required
def index():
    # Lógica da sua página inicial
    return render_template('index.html', nome_usuario=current_user.nome)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        senha = request.form.get('senha')
        user = Usuario.query.filter_by(login=login).first()

        if not user or not check_password_hash(user.senha_hash, senha):
            flash('Login ou senha inválidos. Por favor, tente novamente.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você foi desconectado com sucesso.', 'success')
    return redirect(url_for('login'))

# Adicione aqui o resto das suas rotas (atividades, pedidos, etc.)


# --- Comandos CLI para gerenciar o app ---
@app.cli.command("create-db")
def create_db():
    """Cria as tabelas do banco de dados."""
    with app.app_context():
        db.create_all()
        print("Banco de dados criado com sucesso!")

@app.cli.command("create-admin")
def create_admin_user():
    """Cria um usuário administrador inicial."""
    with app.app_context():
        login = input("Digite o login do admin: ")
        nome = input("Digite o nome do admin: ")
        senha = input("Digite a senha do admin: ")

        user_exists = Usuario.query.filter_by(login=login).first()
        if user_exists:
            print(f"Usuário com login '{login}' já existe.")
            return

        hashed_password = generate_password_hash(senha, method='pbkdf2:sha256')
        new_admin = Usuario(login=login, nome=nome, senha_hash=hashed_password, is_admin=True)
        db.session.add(new_admin)
        db.session.commit()
        print(f"Usuário administrador '{login}' criado com sucesso!")


# O trecho abaixo não é necessário para o deploy no Render com Gunicorn,
# mas é útil para rodar o app localmente com o comando 'python app.py'
if __name__ == '__main__':
    app.run(debug=True)
