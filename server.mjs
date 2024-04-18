import fs from 'fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const __dirname = dirname(fileURLToPath(import.meta.url));

import bcrypt from 'bcrypt';
const saltRounds = 12;

import generatePassword from 'password-generator';

import Database from 'better-sqlite3';

const db = new Database('./db/database.sqlite');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username VARCHAR(128),
	email VARCHAR(255),
	password VARCHAR(255)
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid INTEGER,
    code VARCHAR(6),
    expireDate DATE
);
CREATE TABLE IF NOT EXISTS contactus (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text VARCHAR(4096)
);
DROP TABLE products;
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(512),
    product VARCHAR(255),
    company VARCHAR(255),
    imgurl VARCHAR(1024),
    pdfurl VARCHAR(1024),
    about VARCHAR(2048)
);
INSERT INTO products (name, product, company, imgurl, pdfurl, about) 
    VALUES
    ('Пылесос Samsung S22 Ultra', 'Пылесосы', 'Samsung', 'https://s13emagst.akamaized.net/products/882/881948/images/res_8524260a4b95980a5a32ce0c8bb55d83.jpg', 'https://fotosklad.ru/upload/iblock/f45/f45614686dbd33e10c43198b284ebf48.pdf', 'Пылесос Samsung - это современное устройство для эффективной уборки вашего дома. Он обладает мощным всасыванием и различными насадками для уборки на различных поверхностях'),
    ('Чайник Xiaomi 12 Lite', 'Чайники', 'Xiaomi', 'https://avatars.mds.yandex.net/i?id=1a14ad03905d1d891469eb74d603dd5df54967aa-4589919-images-thumbs&n=13', 'https://www.fotosklad.ru/upload/iblock/1a6/1a6c6f450bff80e15d4f5125a84ef196.pdf', 'Чайник Xiaomi - это элегантное и инновационное устройство для кипячения воды, выпущенное компанией Xiaomi. Он отличается стильным дизайном и высоким качеством материалов, что делает его привлекательным элементом кухонного интерьера'),
    ('Утюг LG 9S', 'Утюги', 'LG', 'https://avatars.mds.yandex.net/i?id=9a40f1b5e135a921cfa04fb41ede1477b22374bc-9100543-images-thumbs&n=13', 'https://abc.ru/upload/instructions/jr/bu/1540210256.5476jrburbz2inskqamo0fxthr_nlgwrooeikl2q.pdf', 'Утюг LG 9S - это стильный и эффективный утюг, который обеспечивает отличное качество глажения вашей одежды. Снабженный инновационной технологией и высококачественными материалами'),
    ('Микроволновка Samsung F3', 'Микроволновки', 'Samsung', 'https://avatars.mds.yandex.net/i?id=2a9ef97658b65de2dc5ca02d0c50b3e4e3169508-12480075-images-thumbs&n=13', 'https://www.fotosklad.ru/upload/iblock/7ed/7eda7b20ab417b6adf9647712c768f24.pdf', 'Микроволновка Samsung F3 - это высококачественное устройство, предназначенное для быстрого и удобного приготовления пищи. Она сочетает в себе надежность, функциональность и современный дизайн, делая ее привлекательным выбором для кухни'),
    ('Микроволновка Xiaomi Mijia23', 'Микроволновки', 'Xiaomi', 'https://avatars.mds.yandex.net/i?id=fca9c55802703f812fac72c2fbb97f9ffbab7827-8306996-images-thumbs&n=13', 'https://ultratrade.ru/files/products/Xiaomi_Mijia_Microwave_Oven_MWBLXE1ACM_manual_RUS71009_1633684867_72725.pdf', 'Микроволновка Xiaomi Mijia23 - это высококачественное устройство, предназначенное для быстрого и удобного приготовления пищи. Она сочетает в себе надежность, функциональность и современный дизайн, делая ее привлекательным выбором для кухни');
`);

import express from 'express';
import ejs from 'ejs'
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser'


const privateKey = fs.readFileSync(__dirname + '/private.key');
const app = express();
console.log("");
app.set('view engine', 'ejs');
app.set('views', __dirname + '/front');
app.use(express.json());
app.use(cookieParser());
app.use('/static', express.static(__dirname + '/public'));

import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
	service: "gmail",
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: "theerden.kenzhebaev.2006@gmail.com",
    pass: "your_password",
  },
});

const sendMail = async (mailDetails, callback) => {
    const info = await transporter.sendMail(mailDetails);
    callback(info);
};

app.post('/api/register', (req, res) => {
    try {
        let username = req.body.username;
        let email = req.body.email;
        let password = req.body.password;
        if (!username) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "username",
                "code": 0,
                "message": "Please, specify username"
            });
            return;
        }
        if (!email) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "email",
                "code": 0,
                "message": "Please, specify Email"
            });
            return;
            
        }
        if (!password) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "password",
                "code": 0,
                "message": "Please, specify password"
            });
            return;
        }
        const checkUsrName = db.prepare('SELECT id FROM users WHERE username = ?');
        const isUsrNameTaken = checkUsrName.get(username);
        if (isUsrNameTaken) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "username",
                "message": "Username is already taken"
            });
            return;
        }
        
        const isUsrNameValid = /^(?![-_])(^[a-zA-Z0-9-_]{3,18}\s*$)/.test(username);
        if (!isUsrNameValid) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "username",
                "code": 1,
                "message": "Неправильное имя пользователя. Используйте только латинские символы и - _"
            });
            return;
        }
        username = username.replace(/\s/g, "");
        
        const isEmailValid = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/.test(email);
        if (!isEmailValid) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "email",
                "code": 1,
                "message": "Email is not satisfying requirements"
            });
            return;
        }
        
        const isPassValid = /^[a-zA-Zа-яА-Я0-9$@!%*#?&.-_]{8,32}\s*$/.test(password);
        const isCapitals = /[A-ZА-Я]/.test(password);
        const isNumbers = /[0-9]/.test(password);
        const isSymbols = /[$@!%*#?&.-_]/.test(password);
        if (isPassValid * isCapitals * (isNumbers + isSymbols) == false) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "password",
                "code": 1,
                "message": "Пароль должен быть объемом от 8 до 32 символов и должен состоять хотя-бы из одной цифры и печатной буквы"
            });
            return;
        }
        password = password.replace(/\s/g, "");
        
        //const checkEmail = db.prepare('SELECT id FROM users WHERE email = ?');
        //const result2 = checkEmail.get(email);
        //if (result2) {
        //    res.status(400);
        //    res.json({
        //        "status": 1,
        //        "bad": "email",
        //        "message": "Email is already taken"
        //    });
        //    return;
        //} ------------------------Its for production
        const setUsr = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
        bcrypt.hash(password, saltRounds, function(err, hash) {
            if (err) {
                res.status(500);
                res.json({
                    "status": 2,
                    "message": "Server Error. Try again later"
                });
                console.error(err);
                return;
            }
            setUsr.run(username, email, hash);
            res.status(200);
            res.json({
                "status": 0,
                "message": "Successfully registered"
            });
        });
        return;
    } catch (err) {
        res.status(500);
        res.json({
            "status": 2,
            "message": "Server Error. Try again later"
        });
        console.error(err);
    }
});

app.post('/api/login', (req, res) => {
    try {
        let username = req.body.username;
        const password = req.body.password;
        let resultdb;
        if (!username) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "username",
                "message": "No username"
            });
            return;
        }
        if (!password) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "password",
                "message": "No password"
            });
            return;
        }
        if (/(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/.test(username)) {
            const getPassByEmail = db.prepare('SELECT id, password, email, username FROM users WHERE email = ?');
            resultdb = getPassByEmail.get(username);
            username = resultdb.username;
        } else {
            const getPassByUserName = db.prepare('SELECT id, password, email FROM users WHERE username = ?');
            resultdb = getPassByUserName.get(username);
        }
        if (!resultdb) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "username",
                "message": "Wrong credentials"
            });
            return;
        }
        bcrypt.compare(password, resultdb.password, function(err, result) {
            if (err) {
                res.status(500);
                res.json({
                    "status": 2,
                    "message": "Ошибка сервера. Попробуйте позже"
                });
                console.error(err);
                return;
            }
            if (!result) {
                res.status(400);
                res.json({
                    "status": 1,
                    "bad": "password",
                    "message": "Wrong password"
                });
                return;
            }
            const token = jwt.sign({
                userid: resultdb.id
            }, privateKey, { expiresIn: '1d' });
            
            res.cookie('authtoken', token, {
                maxAge: 86_400_000,
                httpOnly: true,
                sameSite: 'strict',
                secure: true
            });
            res.status(200);
            console.log('User ' + username + ' has been logged in');
            res.json({
                "status": 0,
                "message": "Вход прошел успешно!"
            });
        });
    } catch (err) {
        res.status(500);
        res.json({
            "status": 2,
            "message": "Ошибка сервера. Попробуйте позже" 
        });
        console.error(err);
    }
});

app.get('/api/logout', (req, res) => {
    try {
        res.clearCookie("authtoken"); // Очистка JWT для выхода из аккаунта
        res.status(200);
        res.json({
            "status": 0,
            "message": "Logged out"
        });
    } catch (err) {
        res.status(500); // ну блиин
        res.json({
            "status": 2,
            "message": "Server error. Try again later"
        });
        console.error(err);
    }
});


app.post('/api/sendcode', (req, res) => {
    try {
        let username = req.body.username;
        let email = req.body.username;
        if (!username) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "username",
                "message": "No username"
            });
            return;
        }
        const isEmail = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/.test(username);
        let userdb;
        if (isEmail) {
            const getUser = db.prepare('SELECT id, username FROM users WHERE email = ?');
            userdb = getUser.get(username);
            username = userdb.username
            if (!userdb) {
                res.status(400);
                res.json({
                    "status": 1,
                    "bad": "username",
                    "message": "Email not found"
                });
                return;
            }
        } else {
            const getUser = db.prepare('SELECT id, email FROM users WHERE username = ?');
            userdb = getUser.get(username);
            email = userdb.email;
            if (!userdb) {
                res.status(400);
                res.json({
                    "status": 1,
                    "bad": "username",
                    "message": "Username not found"
                });
                return;
            }
        }
        const userid = userdb.id;
        const code = Math.floor(Math.random() * 1000000);
        const setCode = db.prepare('INSERT INTO recovery_codes (userid, code) VALUES(?, ?)');
        const insertCode = setCode.run(userid, code); // Создание записи кода восстановления в базе данных
        const token = jwt.sign({
            codeid: insertCode.lastInsertRowid
        }, privateKey, { expiresIn: '30m' });
        res.cookie('recoverycode', token, { // Создание JWT для кода восстановления только на 30 минут
            maxAge: 1_800_000,
            httpOnly: true,
            sameSite: 'strict',
            secure: true
        });
        sendMail({
            from: 'theerden.kenzhebaev.2006@gmail.com',
            to: email,
            subject: 'Базы данных. Кенжебаев Ерден',
            text: code + ' - Ваш код восстановления',
        }, (data) => {
            res.json({
                "status": 0,
                "message": "Email был отправлен вам на почту. Проверьте папку спам!"
            });
        })
            .catch(err => {
                res.status(500);
                res.json({
                    "status": 2,
                    "message": "Ошибка сервера. Попробуйте позже"
                });
                console.error(err);
            });
    } catch (err) {
        res.status(500);
        res.json({
            "status": 2,
            "message": "Ошибка сервера. Попробуйте позже"
        });
        console.error(err);
    }
});

// Апи для проверки кода восстановления на валидность
app.post('/api/checkcode', (req, res) => {
    try {
        const code = req.body.code;
        if (!code) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "code",
                "message": "Введите код"
            });
            return;
        }
        const token = req.cookies.recoverycode;
        if (!token) {
            res.status(400);
            res.json({
                "status": 3,
                "redirect": "/"
            });
            return;
        }
        const codeid = jwt.verify(token, privateKey).codeid;
        const getCode = db.prepare('SELECT userid, code FROM recovery_codes WHERE id = ?');
        const codedb = getCode.get(codeid);
        if (Math.floor(codedb.code).toString() !== Math.floor(code).toString()) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "code",
                "message": "Неправильный код!"
            });
            return;
        }
        const getUser = db.prepare('SELECT username, email FROM users WHERE id = ?');
        const userdb = getUser.get(codedb.userid);
        const username = userdb.username;
        const email = userdb.email;
        const updateUser = db.prepare('UPDATE users SET password = ? WHERE id = ?');
        const newPassword = generatePassword(16, false);
        bcrypt.hash(newPassword, saltRounds, function(err, hash) {
            if (err) {
                res.status(500);
                res.json({
                    "status": 2,
                    "message": "Ошибка сервера. Попробуйте позже"
                });
                console.error(err);
                return;
            }
            updateUser.run(hash, codedb.userid);
            const token = jwt.sign({
                userid: codedb.userid
            }, privateKey, { expiresIn: '1h' });
            res.cookie('authtoken', token, { // JWT токен авторизации на 1 час на восстановление пароля
                maxAge: 3_600_000,
                httpOnly: true,
                sameSite: 'strict',
                secure: true
            });
            res.clearCookie("recoverycode"); // Удаление не нужного токена для кода восстановления
            res.status(200);
            res.json({
                "status": 0,
                "message": "Now, recover your password on https://erduha.xyz/recover" // По сути редайрект
            });
        });
    } catch (err) {
        res.status(500);
        res.json({
            "status": 2,
            "message": "Ошибка сервера. Попробуйте позже"
        });
        console.error(err);
    }
})

// Апи для смены пароля
app.post('/api/recover', (req, res) => {
    try {
        let userid;
        try {
            const token = req.cookies.authtoken;
            userid = jwt.verify(token, privateKey).userid;
        } catch {
            res.status(400);
            res.redirect('/');
            return;
        }
        const password1 = req.body.password1;
        const password2 = req.body.password2;
        if (!password1) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "password1",
                "message": "Please, specify password"
            });
            return;
        }
        if (!password2) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "password2",
                "message": "Please, repeat password"
            });
            return;
        }
        if (password1 !== password2) {
            res.status(400);
            res.json({
                "status": 1,
                "bad": "password2",
                "message": "Passwords don't match!"
            });
            return;
        }
        const updatePassword = db.prepare('UPDATE users SET password = ? WHERE id = ?');
        bcrypt.hash(password1, saltRounds, function(err, hash) { // Асинхронное хэширование пароля
            if (err) { // Ошибки фу, плохой код фу, посмотри на мою эстетику
                res.status(500);
                res.json({
                    "status": 2,
                    "message": "Ошибка сервера. Попробуйте позже"
                });
                return;
            }
            updatePassword.run(hash, userid); // Изменение пароля в базе данных
            const token = jwt.sign({ // Создание JWT
                userid: userid
            }, privateKey, { expiresIn: '1d' });
            res.cookie('authtoken', token, { // JWT токен авторизации на 1 день
                maxAge: 86_400_000,
                httpOnly: true,
                sameSite: 'strict',
                secure: true
            });
            res.status(200);
            res.json({
                "status": 0,
                "message": "Password has changed successfully!"
            });
        });
    } catch {
        res.status(500);
        res.json({
            "status": 2,
            "message": "Ошибка сервера. Попробуйте позже"
        });
    }
});

app.get('/api/getproducts', (req, res) => {
    try {
        const getProducts = db.prepare('SELECT * FROM products');
        const products = getProducts.all();
        res.status(200)
        res.json(products);
    } catch {
        res.status(500);
        res.json({
            "status": 2,
            "message": "Ошибка сервера. Попробуйте позже"
        });
    }
});

app.post('/api/contactus', (req, res) => {
    try {
        const text = req.body.text;
        const insertContactUs = db.prepare('INSERT INTO TABLE contactus (text) VALUES(?)');
        insertContactUs(text);
    } catch {
        res.status(500);
        res.json({
            "status": 2,
            "message": "Ошибка сервера. Попробуйте позже"
        });
    }
});

app.get('/api/get-contactus', (req, res) => {
    try {
        const getContactus = db.prepare('SELECT * FROM contactus');
        res.json(getContactus.all())
    } catch {
        res.status(500);
        res.json({
            "status": 2,
            "message": "Ошибка сервера. Попробуйте позже"
        });
    }
});

// Страничка регистрации
app.get('/register', (req, res) => {
    try {
        const token = req.cookies.authtoken;
        const userId = jwt.verify(token, privateKey).userid;
        const getUserName = db.prepare('SELECT username FROM users WHERE id = ?');
        const username = getUserName.get(userId).username;
        if (username) {
            res.redirect('/account');
            return;
        }
    } catch {}
    res.sendFile(__dirname + '/front/logreg/register.html');
});

// Страничка входа в аккаунт
app.get('/login', (req, res) => {
    try {
        const token = req.cookies.authtoken;
        const userId = jwt.verify(token, privateKey).userid;
        const getUserName = db.prepare('SELECT username FROM users WHERE id = ?');
        const username = getUserName.get(userId).username;
        if (username) {
            res.redirect('/account');
            return;
        }
    } catch {}
    res.sendFile(__dirname + '/front/logreg/login.html');
});


// Страничка вашего аккаунта.
app.get('/account', (req, res) => {
    let username = '';
    let email = '';
    try {
        const token = req.cookies.authtoken;
        const userId = jwt.verify(token, privateKey).userid;
        const getUser = db.prepare('SELECT username, email FROM users WHERE id = ?');
        const userdb = getUser.get(userId);
        username = userdb.username;
        let isDomain = false;
        for (let i = 0; i < userdb.email.length; i++) {
            if (userdb.email[i] === "@") {
                isDomain = true;
            }
            if (i < 4 || isDomain === true) {
                email += userdb.email[i];
            } else {
                email += '*';
            }
        }
    } catch {
        res.status(400);
        res.redirect('/login');
        return;
    }
    res.status(200);
    res.render('logreg/account', {
        username: username,
        email: email
    });
});

// Страничка, для тех, кто забыл пароль
app.get('/forgot-password', (req, res) => {
    res.sendFile(__dirname + '/front/logreg/forgot.html');
});

// Страничка проверки кода на валидность
app.get('/check-code', (req, res) => {
    try {
        const token = req.cookies.recoverycode;
        jwt.verify(token, privateKey);
    } catch {
        res.status(400);
        res.redirect('/login');
        return;
    }
    res.sendFile(__dirname + '/front/logreg/codecheck.html');
});

// Страничка восстановления пароля. Работает только для уже вошедших пользователей
app.get('/recover', (req, res) => {
    let username;
    try {
        const token = req.cookies.authtoken;
        const userId = jwt.verify(token, privateKey).userid;
        const getUserName = db.prepare('SELECT username FROM users WHERE id = ?');
        username = getUserName.get(userId).username;
    } catch {
        res.status(400);
        res.redirect('/login');
        return;
    }
    res.render('logreg/recover', {username: username});
});
    
// Главная страничка
app.get('/', (req, res) => {
    let username = '';
    try {
        const token = req.cookies.authtoken;
        const userId = jwt.verify(token, privateKey).userid;
        const getUser = db.prepare('SELECT username FROM users WHERE id = ?');
        const userdb = getUser.get(userId);
        username = userdb.username;
    } catch (err) {
        res.status(200);
    	res.render('index', {
    	    username: "Sign up/Login", 
    	    linkacc: "/register"
    	});
    	console.error(err);
    	return;
    }
    res.status(200);
	res.render('index', {
	    username: username, 
	    linkacc: "/account"
	});
});

app.get('/contact-us', (req, res) => {
    let username = '';
    try {
        const token = req.cookies.authtoken;
        const userId = jwt.verify(token, privateKey).userid;
        const getUser = db.prepare('SELECT username FROM users WHERE id = ?');
        const userdb = getUser.get(userId);
        username = userdb.username;
    } catch (err) {
        res.status(200);
    	res.render('contactus', {
    	    username: "Sign up/Login", 
    	    linkacc: "/register"
    	});
    	console.error(err);
    	return;
    }
    res.status(200);
	res.render('contactus', {
	    username: username, 
	    linkacc: "/account"
	});
});

app.get('/products', (req, res) => {
    let username = '';
    try {
        const token = req.cookies.authtoken;
        const userId = jwt.verify(token, privateKey).userid;
        const getUser = db.prepare('SELECT username FROM users WHERE id = ?');
        const userdb = getUser.get(userId);
        username = userdb.username;
    } catch (err) {
        res.status(200);
    	res.render('products', {
    	    username: "Sign up/Login", 
    	    linkacc: "/register"
    	});
    	console.error(err);
    	return;
    }
    res.status(200);
	res.render('products', {
	    username: username, 
	    linkacc: "/account"
	});
});

// Отдельные продукты
app.get('/product/:id', (req, res) => {
    const getProduct = db.prepare('SELECT * FROM products WHERE id = ?');
    const product = getProduct.get(req.params.id);
    res.status(200);
    res.render('productPage', {
        imgurl: product.imgurl,
        name: product.name,
        pdfurl: product.pdfurl,
        about: product.about
    });
});

// You are my sunshine, you are my sunshine
app.get('/sunshine', (req, res) => {
    res.sendFile(__dirname + '/public/my_sunshine.mp4');
});

// 404
app.use(function(req, res, next) {
  res.status(404);

  // Если браузер
  if (req.accepts('html')) {
    res.sendFile(__dirname + '/front/404.html');
    return;
  }

  // Или не браузер
  if (req.accepts('json')) {
    res.json({ error: 'Not found' });
    return;
  }

  // Если вообще что-то старое
  res.type('txt').send('Not found');
});



// Прослушка порта 3000
app.listen(3000, () => {
	console.log('Сайт запустился на https://localhost:3000 или https://erduha.xyz', data => {
	    res.json({
            "message": data
	    });
	});
});
