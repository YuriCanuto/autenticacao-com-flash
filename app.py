from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({'mensagem': 'Login realizado!'}), 200

    return jsonify({'mensagem': 'Credenciais inválidas'}), 422

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'mensagem': 'Logout realizado com sucesso'})

@app.route('/user', methods=['POST'])
# @login_required
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return jsonify({'mensagem': 'Cadastro realizado com sucesso'}), 201
    
    return jsonify({'mensagem': 'Dados inválidos'})

@app.route('/user/<int:user_id>', methods=['GET'])
@login_required
def read_user(user_id):
    user = User.query.get(user_id)

    if user:
        return jsonify({'username': user.username})

    return jsonify({'mensagem': 'Usuário não encontrado'}), 404

@app.route('/user/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    data = request.json
    user = User.query.get(user_id)

    if user_id != current_user.id and current_user.role == 'user':
        return jsonify({'mensagem': 'Operação não permitida'})

    if user and data.get('password'):

        user.password = data.get('password')
        db.session.commit()

        return jsonify({'mensagem': 'Usuário atualizado com sucesso'})

    return jsonify({'mensagem': 'Usuário não encontrado'}), 404

@app.route('/user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)

    if user_id != current_user.id and current_user.role == 'user':
        return jsonify({'mensagem': 'Operação não permitida'})

    if user_id == current_user.id:
        return jsonify({'mensagem': 'Não é permitido deletar o usuário atual'}), 422

    if user:

        db.session.delete(user)
        db.session.commit()

        return jsonify({'mensagem': 'Usuário deletado com sucesso'})
    
    return jsonify({'mensagem': 'Usuário não encontrado'}), 404

if __name__ == '__main__':
    app.run(debug=True)