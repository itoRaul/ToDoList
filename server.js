const express = require('express');
const app = express();
const { pool } = require('./dbConfig.js');
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');
const initializePassport = require('./passportConfig.js');
const path = require('path');

app.use(express.static(path.join(__dirname, 'public')));

initializePassport(passport);

const PORT = process.env.PORT || 3000;

app.set('view engine', "ejs");
app.use(express.urlencoded({ extended: false }));

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());


//ROTAS DE AUTENTICAÇÃO
app.get('/', (req, res) => {
    res.render('index.ejs');
});

app.get('/users/register', checkAuthenticated, (req, res) => {
    res.render('register.ejs');
});

app.get('/users/login', checkAuthenticated, (req, res) => {
    res.render('login.ejs');
});

app.get('/users/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        req.flash("success_msg", "Você foi desconectado!");
        res.redirect('/users/login');
    });
});

app.post('/users/register', async (req, res) => {
    let { name, email, password, password2 } = req.body;
    let errors = [];

    if (password.length < 6) {
        errors.push({ message: "A senha deve ter pelo menos 6 caracteres" });
    }
    if (password != password2) {
        errors.push({ message: "As senhas inseridas não são iguais" });
    }

    if (errors.length > 0) {
        res.render('register.ejs', { errors });
    } else {
        let hashedPassword = await bcrypt.hash(password, 10);
        pool.query('SELECT * FROM users WHERE email = $1', [email], (err, results) => {
            if (err) {
                throw err;
            }
            if (results.rows.length > 0) {
                errors.push({ message: "Esse email já está cadastrado" });
                res.render('register.ejs', { errors });
            } else {
                pool.query('INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, password', [name, email, hashedPassword], function (err, results) {
                    if (err) {
                        throw err;
                    }
                    req.flash("success_msg", "Usuário cadastrado com sucesso!");
                    res.redirect('/users/login');
                })
            }
        });
    }
});

app.post('/users/login', passport.authenticate('local', {
    successRedirect: '/users/todolist',
    failureRedirect: '/users/login',
    failureFlash: true
}));


// ROTAS DA TODOLIST 

// ROTA PRINCIPAL DA LISTA - LER
app.get('/users/todolist', checkNotAuthenticated, async (req, res) => {
    try {
        const userId = req.user.id;
        const result = await pool.query('SELECT * FROM tasks WHERE user_id = $1 ORDER BY created_at DESC', [userId]);
        
        res.render('todolist.ejs', { user: req.user, tasks: result.rows });
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Não foi possível carregar as tarefas.');
        res.redirect('/');
    }
});

// ROTA PARA ADICIONAR TAREFA - CRIAR
app.post('/users/tasks/add', checkNotAuthenticated, async (req, res) => {
    const { title } = req.body;
    const userId = req.user.id;

    if (title && title.trim() !== '') {
        try {
            await pool.query('INSERT INTO tasks (title, user_id) VALUES ($1, $2)', [title.trim(), userId]);
            req.flash('success_msg', 'Tarefa adicionada!');
        } catch (err) {
            console.error(err);
            req.flash('error_msg', 'Ocorreu um erro ao adicionar a tarefa.');
        }
    } else {
        req.flash('error_msg', 'O título da tarefa não pode ser vazio.');
    }
    res.redirect('/users/todolist');
});

// ROTA PARA APAGAR TAREFA - APAGAR (DELETE)
app.post('/users/tasks/delete/:id', checkNotAuthenticated, async (req, res) => {
    const taskId = req.params.id;
    const userId = req.user.id;

    try {
        const result = await pool.query('DELETE FROM tasks WHERE id = $1 AND user_id = $2', [taskId, userId]);

        if (result.rowCount > 0) {
            req.flash('success_msg', 'Tarefa apagada!');
        } else {
            req.flash('error_msg', 'Não foi possível apagar a tarefa. Talvez ela não exista ou não pertença a você.');
        }
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Ocorreu um erro ao apagar a tarefa.');
    }
    res.redirect('/users/todolist');
});

// ROTA PARA MOSTRAR A PÁGINA DE EDIÇÃO
app.get('/users/tasks/edit/:id', checkNotAuthenticated, async (req, res) => {
    const taskId = req.params.id;
    const userId = req.user.id;

    try {
        const result = await pool.query('SELECT * FROM tasks WHERE id = $1 AND user_id = $2', [taskId, userId]);
        if (result.rows.length === 0) {
            req.flash('error_msg', 'Tarefa não encontrada.');
            return res.redirect('/users/todolist');
        }
        res.render('edit.ejs', { task: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.redirect('/users/todolist');
    }
});

// ROTA PARA ATUALIZAR TAREFA - ATUALIZAR
app.post('/users/tasks/update/:id', checkNotAuthenticated, async (req, res) => {
    const taskId = req.params.id;
    const { title } = req.body;
    const userId = req.user.id;

    if (title && title.trim() !== '') {
        try {
            const result = await pool.query('UPDATE tasks SET title = $1 WHERE id = $2 AND user_id = $3', [title.trim(), taskId, userId]);
            if (result.rowCount > 0) {
                req.flash('success_msg', 'Tarefa atualizada!');
            } else {
                req.flash('error_msg', 'Não foi possível atualizar a tarefa.');
            }
        } catch (err) {
            console.error(err);
            req.flash('error_msg', 'Ocorreu um erro ao atualizar a tarefa.');
        }
    } else {
        req.flash('error_msg', 'O título da tarefa não pode ser vazio.');
    }
    res.redirect('/users/todolist');
});


// FUNÇÕES DE MIDDLEWARE
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/users/todolist');
    }
    next();
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/users/login');
}

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
