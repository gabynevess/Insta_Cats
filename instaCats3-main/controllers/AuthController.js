//1º PRECISO importar o arquivo de modulo
const User = require('../models/User');
const bcrypt = require('bcryptjs');

module.exports = class AuthController{
    static login(request, response){
        //render -> diretório do projeto - nomeArquivo
        //redirect -> Mandar para uma ROTA - /
        return response.render('auth/login')
    }

    static async loginPost(request, response) {
        const { email, password } = request.body;

        console.log(email, password);

        //Verificar se o usuário existe
        const user = await User.findOne({ where: { email: email } });
        if(!user) {
            request.flash('message', 'Usuário não encontrado');
            response.render('home')
            return
        }

        // console.log(user);

        //Validação das senhas
        const passwordMath = bcrypt.compareSync(password, user.password);
        if(!passwordMath) {
            request.flash('message', 'Senha inválida');
            response.render('home')
            return
        }

        request.session.userId = user.id

        request.flash('message', 'Autentificação realizada com sucesso!');
        request.session.save(() => {
            response.redirect('/')
        })
    }

    static register(request, response){
        return response.render('auth/register');
    }

    static async registerPost(request, response){
        const { name, email, password, passwordConfirm } = request.body

        // console.log(name, email, password, passwordConfirm);

        if(password != passwordConfirm) {
            request.flash('message', 'As senhas não conferem. Tente novamente');
            response.render('home')
            return
        }

        // Validação de o usuário já existe
        const checkIfUserExist = await User.findOne({ where: { email: email } });
        if(checkIfUserExist) {
            request.flash('message', 'O email já está em uso');
            response.render('home')
            return
        }

        //Criptografar a senha do usuário
        //
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);
        
        const user = {
            name,
            email,
            password: hashedPassword
        }

        try {
            const createdUser = await User.create(user);

            request.session.userId = createdUser.id;

            request.flash('message', 'Cadastro realizado com sucesso!');

            request.session.save(() => {
              return response.redirect('/');
            })
        } catch (error) {
            console.error(error);
        }
    }

    static async logout(request, response){
        request.session.destroy();
        response.redirect('/')
    }

}