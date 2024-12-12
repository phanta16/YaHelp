import ast
import os
import random
import sqlite3
import sys

import bcrypt
import fake_useragent
import requests
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap, QFont
from PyQt6.QtWidgets import QApplication, QLabel, QMainWindow, QPushButton, QTextEdit, QWidget, QLineEdit
from g4f.client import Client
from selenium import webdriver

salt = b'$2b$12$GeiYKSCgQkuESrvPhcGKSe'

current_user = '1'

flag = False

def get_info(data):
    global flag
    if not flag:
        if len(data[0][0]) == 0:
            return False
    cookie = ast.literal_eval(data[0][0])
    uk = fake_useragent.UserAgent()
    cookies = {}
    headers = {'User-Agent': uk.random}
    for i in cookie:
        cookies[i['name']] = i['value']
    s = requests.Session()
    respond = s.get(url='https://lms.yandex.ru/api/profile', headers=headers, cookies=cookies)
    flag = True
    return respond.json()


def hash_password(password, salt, password2):
    if password2 is None:
        hashed = bcrypt.hashpw(password.encode(), salt).decode()
        return hashed
    else:
        hashed = bcrypt.hashpw(password2.encode(), salt).decode()
        if hashed != password:
            return False
        else:
            return True


def checker(login, password):
    if login == '' or password == '':
        return 52

    if len(password) < 5:
        return 102
    return 100

class Authorization(QWidget):

    def __init__(self):
        super().__init__()
        self.initui()
        self.con = sqlite3.connect('users_auth.db')
        self.cur = self.con.cursor()

    def initui(self):
        self.au = QLabel()
        self.rand_conf = str(random.randint(1, 6))
        self.setGeometry(450, 150, 1000, 800)
        self.setWindowTitle('YaHelp')
        self.backgr()
        self.authwindow()
        self.auth()

    def backgr(self):
        self.back = QLabel(self)
        self.back.setGeometry(0, 0, 1000, 800)
        image_path = self.randomimage()
        pixmap = QPixmap(image_path)
        self.back.setPixmap(pixmap)
        self.back.setScaledContents(True)
        self.back.lower()

    def authwindow(self):
        self.au = QLabel(self)
        self.au.setGeometry(250, 100, 500, 500)
        image_path = 'auth_window.jpg'
        pixmap = QPixmap(image_path)
        self.au.setPixmap(pixmap)
        self.label = QLabel(self)
        self.label.setGeometry(355, 0, 400, 400)
        image_path1 = 'label.jpg'
        pixmap1 = QPixmap(image_path1)
        self.label.setPixmap(pixmap1)

    def auth(self):
        self.font = QFont('Arial, 10')
        self.font.setBold(True)

        self.btn_auth = QPushButton(self)
        self.btn_auth.setGeometry(450, 490, 120, 60)
        self.btn_auth.setText('Войти')
        self.btn_auth.setFont(self.font)
        self.btn_auth.setStyleSheet(
            "background-color: #FD3039;"
            "color: white;"
            "border-radius: 30px;"
            "font-size: 20px;")
        self.btn_auth.clicked.connect(self.auth_st1)
        self.ipaspole = QLineEdit(self, echoMode=QLineEdit.EchoMode.Password)
        self.ipaspole.setGeometry(411, 390, 200, 60)
        self.ipaspole.setPlaceholderText('Пароль')
        self.ipaspole.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ipaspole.setFont(self.font)
        self.ipaspole.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 20px;")
        self.ilogpole = QLineEdit(self)
        self.ilogpole.setGeometry(411, 310, 200, 60)
        self.ilogpole.setPlaceholderText('Логин')
        self.ilogpole.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ilogpole.setFont(self.font)
        self.ilogpole.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 20px;")

    def randomimage(self):
        for i in os.listdir(os.getcwd()):
            if 'sc' in i and self.rand_conf in i:
                return i

    def auth_st1(self):
        global curr_data

        login = self.ilogpole.text()
        password = self.ipaspole.text()
        if checker(login, password) == 100:
            pass

        if checker(login, password) == 52:
            print('Не все поля заполнены!')
            raise TypeError('Не все поля заполнены!')

        if checker(login, password) == 102:
            print('Пароль должен быть минимум 5 символов!')
            raise IndexError('Пароль должен быть минимум 5 символов!')

        if self.cur.execute(
                '''SELECT * FROM USER_DATA WHERE EXISTS (SELECT * FROM USER_DATA WHERE LOGIN LIKE ?)''', (login,)):
            password_ready = self.cur.execute('''SELECT * FROM USER_DATA WHERE LOGIN LIKE ?''', (login,)).fetchone()
            if password_ready is None:
                self.cur.execute('''INSERT INTO USER_DATA(LOGIN, PASSWORD) VALUES(?, ?)''',
                                 (login, hash_password(password, salt, None)))
                self.con.commit()
                a.hide()
                self.curr_user(login)
                c.show()
            elif password_ready is not None:
                password_ready = password_ready[1]
                if hash_password(password_ready, salt, password):
                    self.hide()
                    self.curr_user(login)
                    main.show()
                else:
                    print('Неверный пароль!')
                    raise IndexError('Неверный пароль!')

    def curr_user(self, login):
        global current_user
        current_user = login


class CookieGraber(QWidget):
    def __init__(self):
        super().__init__()
        self.initui()
        self.con = sqlite3.connect('users_auth.db', timeout=10)
        self.cur = self.con.cursor()

    def initui(self):
        self.font = QFont('Arial, 10')
        self.font.setBold(True)

        self.au = QLabel(self)
        self.au.setGeometry(0, 0, 1000, 1000)
        image_path = 'auth_window.jpg'
        pixmap = QPixmap(image_path)
        self.au.setPixmap(pixmap)

        self.au = QLabel
        self.setGeometry(450, 150, 1000, 800)
        self.setWindowTitle('YaHelp')

        self.label = QLabel(self)
        self.label.setGeometry(355, -120, 400, 400)
        image_path1 = 'label.jpg'
        pixmap1 = QPixmap(image_path1)
        self.label.setPixmap(pixmap1)

        self.btn_cook = QPushButton(self)
        self.btn_cook.setGeometry(450, 490, 120, 60)
        self.btn_cook.setText('Войти')
        self.btn_cook.setFont(self.font)
        self.btn_cook.setStyleSheet(
            "background-color: #FD3039;"
            "color: white;"
            "border-radius: 30px;"
            "font-size: 20px;")
        self.btn_cook.clicked.connect(self.cookie_first)

        self.cookielabel = QLabel(self)
        self.cookielabel.setGeometry(160, 190, 1000, 200)
        self.cookielabel.setText(f'Следуйте инструциям на экране и по окончанию нажмите Enter')
        self.cookielabel.setFont(self.font)
        self.cookielabel.setStyleSheet(
            "color: black;"
            "font-size: 20px;")

    def cookiegrab(self):
        self.browser = webdriver.Chrome()
        self.browser.get('https://passport.yandex.ru/')
        keyboard.read_key()
        cooki = self.cook()
        global current_user
        if 'Medium' not in self.cookiepole.text():
            print('Неверно введены cookie!')
            raise Exception('Неверно введены cookie!')
        else:
            self.cur.execute('''UPDATE USER_DATA SET COOKIES = ? WHERE LOGIN LIKE ?''',
                             (cooki, current_user))
            self.con.commit()
            self.hide()
            main.show()
            self.browser.quit()

    def cookie_first(self):
        self.browser = webdriver.Chrome()
        self.browser.get('https://passport.yandex.ru/')

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Return:
            cooki = self.cook()
            global current_user
            self.cur.execute('''UPDATE USER_DATA SET COOKIES = ? WHERE LOGIN LIKE ?''',
                             (str(cooki), current_user))
            self.con.commit()
            self.hide()
            main.show()
            self.browser.quit()

    def cook(self):
        cookies_raw = self.browser.get_cookies()
        return cookies_raw


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.initui()
        self.con = sqlite3.connect('users_auth.db', timeout=10)
        self.cur = self.con.cursor()

    def initui(self):
        self.au = QLabel
        self.setGeometry(300, 100, 1000, 900)
        self.setWindowTitle('YaHelp')
        self.main()
        self.client = Client()

    def main(self):
        self.con = sqlite3.connect('users_auth.db', timeout=10)
        self.cur = self.con.cursor()
        global current_user
        cookies = self.cur.execute('''SELECT COOKIES FROM USER_DATA WHERE LOGIN LIKE ?''', (current_user,)).fetchall()
        self.font = QFont('Arial, 30')
        self.font.setBold(True)
        self.au = QLabel(self)
        self.au.setGeometry(0, 0, 1000, 1000)
        image_path = 'auth_window.jpg'
        pixmap = QPixmap(image_path)
        self.au.setPixmap(pixmap)
        self.label = QLabel(self)
        self.label.setGeometry(370, -150, 500, 500)
        image_path1 = 'label_smaller.jpg'
        pixmap1 = QPixmap(image_path1)
        self.label.setPixmap(pixmap1)
        self.rating = QLabel(self)
        self.rating.setGeometry(260, 150, 500, 200)
        if get_info(cookies) is False:
            self.rating.setText(
                f'Ваш текущий балл: #.##')
        elif get_info(cookies) is True:
            self.rating.setText(
                f'Ваш текущий балл: {round(get_info(cookies)['coursesSummary']['student'][2]['rating'], 2)}')
        self.rating.setFont(self.font)
        self.rating.setStyleSheet(
            "color: black;"
            "font-size: 40px;")
        self.rating.show()
        self.btn_chat = QPushButton(self)
        self.btn_chat.setGeometry(10, 190, 60, 60)
        self.btn_chat.setText('✉')
        self.btn_chat.setFont(self.font)
        self.btn_chat.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 50px;")
        self.btn_chat.clicked.connect(self.chat)
        self.btn_chat.show()
        self.btn_settings = QPushButton(self)
        self.btn_settings.setGeometry(10, 50, 60, 60)
        self.btn_settings.setText('⚙')
        self.btn_settings.setFont(self.font)
        self.btn_settings.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: white;"
            "border-radius: 30px;"
            "font-size: 4"
            "0px;")
        self.btn_settings.clicked.connect(self.sett)
        self.btn_settings.show()
        self.btn_loggs = QPushButton(self)
        self.btn_loggs.setGeometry(10, 120, 60, 60)
        self.btn_loggs.setText('🕮')
        self.btn_loggs.setFont(self.font)
        self.btn_loggs.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 40px;")
        self.btn_loggs.show()
        self.btn_loggs.clicked.connect(self.logs)
        self.requepole = QTextEdit(self)
        self.requepole.setGeometry(30, 560, 900, 270)
        self.requepole.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.requepole.setPlaceholderText('Введите ваш запрос')
        self.requepole.setFont(self.font)
        self.requepole.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 20px;")
        self.requepole.show()
        self.btn_post = QPushButton(self)
        self.btn_post.setGeometry(700, 480, 150, 60)
        self.btn_post.setText('Спросить')
        self.btn_post.setFont(self.font)
        self.btn_post.setStyleSheet(
            "background-color: #FD3039;"
            "color: white;"
            "border-radius: 30px;"
            "font-size: 20px;")
        self.btn_post.show()
        self.btn_post.clicked.connect(self.gpt)

    def refresh(self):
        cookies = self.cur.execute('''SELECT COOKIES FROM USER_DATA WHERE LOGIN LIKE ?''', (current_user,)).fetchall()
        self.rating.setText(
            f'Ваш текущий балл: {round(get_info(cookies)['coursesSummary']['student'][2]['rating'], 2)}')

    def gpt(self):
        global current_user
        res = str(self.requepole.toPlainText())
        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": f'{res}'}],
        )
        self.requepole.setPlainText(response.choices[0].message.content)
        self.cur.execute('''INSERT INTO REQUESTS(USERNAME, REQUEST, ANSWER) VALUES(?, ?, ?)''',
                         (current_user, res, str(self.requepole.toPlainText(), )))
        self.con.commit()

    def sett(self):
        main.hide()
        self.refresh()
        settings.show()

    def logs(self):
        main.hide()
        self.refresh()
        logs.show()

    def chat(self):
        main.hide()
        self.refresh()
        chat.show()


class Settings(QWidget):

    def __init__(self):
        super().__init__()
        self.init()
        self.con = sqlite3.connect('users_auth.db', timeout=10)
        self.cur = self.con.cursor()
        self.au = QLabel
        self.setGeometry(300, 100, 1000, 900)
        self.setWindowTitle('YaHelp')

    def init(self):
        self.font = QFont('Arial, 30')
        self.font.setBold(True)
        self.au = QLabel(self)
        self.au.setGeometry(0, 0, 1000, 1000)
        image_path = 'auth_window.jpg'
        pixmap = QPixmap(image_path)

        self.au.setPixmap(pixmap)
        self.lab = QLabel(self)
        self.lab.setGeometry(100, 15, 800, 600)
        image_path = 'settingimage.jpg'
        pixmap = QPixmap(image_path)
        self.lab.setPixmap(pixmap)

        self.label = QLabel(self)
        self.label.setGeometry(355, -120, 400, 400)
        image_path1 = 'label.jpg'
        pixmap1 = QPixmap(image_path1)
        self.label.setPixmap(pixmap1)

        self.btn_delete = QPushButton(self)
        self.btn_delete.setGeometry(300, 700, 350, 100)
        self.btn_delete.setText('Удалить все данные')
        self.btn_delete.setFont(self.font)
        self.btn_delete.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: red;"
            "border-radius: 30px;"
            "font-size: 30px;")
        self.btn_delete.clicked.connect(self.delete_all)

        self.btn_clear = QPushButton(self)
        self.btn_clear.setGeometry(300, 550, 350, 100)
        self.btn_clear.setText('Очистить историю')
        self.btn_clear.setFont(self.font)
        self.btn_clear.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 30px;")
        self.btn_delete.clicked.connect(self.delete_all)
        self.btn_clear.clicked.connect(self.clear_his)

        self.btn_exit = QPushButton(self)
        self.btn_exit.setGeometry(30, 30, 70, 70)
        self.btn_exit.setText('←')
        self.btn_exit.setFont(self.font)
        self.btn_exit.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 30px;")
        self.btn_exit.clicked.connect(self.exit_button)

    def exit_button(self):
        self.hide()
        main.show()

    def delete_all(self):
        global current_user
        self.cur.execute('''DELETE FROM USER_DATA WHERE USER_DATA.LOGIN LIKE ?''', (current_user,))
        self.con.commit()
        sys.exit()

    def clear_his(self):
        self.cur.execute('''DELETE FROM REQUESTS''')
        self.con.commit()


class Logs(QWidget):
    def __init__(self):
        super().__init__()
        self.current_user = current_user
        self.con = sqlite3.connect('users_auth.db', timeout=10)
        self.cur = self.con.cursor()
        self.init()
        self.au = QLabel(self)
        self.setGeometry(300, 100, 1000, 900)
        self.setWindowTitle('YaHelp')

    def init(self):
        global current_user
        self.font = QFont('Arial, 30')
        self.font.setBold(True)
        self.au = QLabel(self)
        self.au.setGeometry(0, 0, 1000, 1000)
        image_path = 'auth_window.jpg'
        pixmap = QPixmap(image_path)
        self.au.setPixmap(pixmap)

        self.loggstable = QTextEdit(self)
        self.loggstable.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 20px;")
        self.loggstable.setGeometry(30, 160, 900, 500)
        self.loggstable.setReadOnly(True)
        respond = self.cur.execute('''SELECT * FROM REQUESTS
    WHERE REQUESTS.USERNAME LIKE ?''', (current_user,))
        for i in respond:
            self.loggstable.append(f'Запрос: {i[1]}')
            self.loggstable.append(f'Ответ: {i[2]}')
            self.loggstable.append('\n')

        self.btn_exit = QPushButton(self)
        self.btn_exit.setGeometry(30, 30, 70, 70)
        self.btn_exit.setText('←')
        self.btn_exit.setFont(self.font)
        self.btn_exit.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 30px;")
        self.btn_exit.clicked.connect(self.exit_button)

        self.btn_refresher = QPushButton(self)
        self.btn_refresher.setText('🗘')
        self.btn_refresher.setGeometry(350, 700, 250, 100)
        self.btn_refresher.setFont(self.font)
        self.btn_refresher.setStyleSheet(
            "background-color: #FD3039;"
            "color: white;"
            "border-radius: 30px;"
            "font-size: 70px;")
        self.btn_refresher.clicked.connect(self.refresh)
        self.btn_exit.clicked.connect(self.exit_button)

        self.label = QLabel(self)
        self.label.setGeometry(355, -120, 400, 400)
        image_path1 = 'label.jpg'
        pixmap1 = QPixmap(image_path1)
        self.label.setPixmap(pixmap1)

    def is_nodata(self):
        conn = sqlite3.connect('users_auth.db', timeout=10)
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM REQUESTS;")
        count = cursor.fetchone()[0]
        if count > 0:
            return False
        return True

    def refresh(self):
        global current_user
        respond = self.cur.execute('''SELECT * FROM REQUESTS
            WHERE REQUESTS.USERNAME LIKE ?''', (current_user,))
        if self.is_nodata():
            self.loggstable.setText('')
        for i in respond:
            if i[1] not in self.loggstable.toPlainText() or i[2] not in self.loggstable.toPlainText():
                self.loggstable.append(f'Запрос: {i[1]}')
                self.loggstable.append(f'Ответ: {i[2]}')
                self.loggstable.append('\n')

    def exit_button(self):
        self.refresh()
        self.hide()
        main.show()


class Chat(QWidget):
    def __init__(self):
        super().__init__()
        self.current_user = current_user
        self.init()
        self.con = sqlite3.connect('users_auth.db', timeout=10)
        self.cur = self.con.cursor()
        self.au = QLabel
        self.setGeometry(300, 100, 1000, 900)
        self.setWindowTitle('YaHelp')

    def init(self):
        self.con = sqlite3.connect('users_auth.db', timeout=10)
        self.cur = self.con.cursor()
        self.font = QFont('Arial, 30')
        self.font.setBold(True)
        self.au = QLabel(self)
        self.au.setGeometry(0, 0, 1000, 1000)
        image_path = 'auth_window.jpg'
        pixmap = QPixmap(image_path)
        self.au.setPixmap(pixmap)

        self.message_pol = QTextEdit(self)
        self.message_pol.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 20px;")
        self.message_pol.setGeometry(30, 160, 500, 500)
        self.message_pol.setReadOnly(True)

        self.mesenev = QLabel(self)
        self.mesenev.setGeometry(570, -180, 1000, 1000)
        image_path = 'Mesenev_chat.jpg'
        pixmap = QPixmap(image_path)
        self.mesenev.setPixmap(pixmap)
        self.mesenev.setStyleSheet(
            "border-radius: 30px;")

        self.message_input = QTextEdit(self)
        self.message_input.setPlaceholderText('Вводите текст')
        self.message_input.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 20px;")
        self.message_input.setGeometry(30, 730, 900, 100)
        self.refresh()

        self.btn_exit = QPushButton(self)
        self.btn_exit.setGeometry(30, 30, 70, 70)
        self.btn_exit.setText('←')
        self.btn_exit.setFont(self.font)
        self.btn_exit.setStyleSheet(
            "background-color: #FCEBC3;"
            "color: black;"
            "border-radius: 30px;"
            "font-size: 30px;")
        self.btn_exit.clicked.connect(self.exit_button)

        self.mesenev_label = QLabel(self)
        self.mesenev_label.setFont(self.font)
        self.mesenev_label.setGeometry(675, 60, 900, 900)
        self.mesenev_label.setText('Куратор')
        self.mesenev_label.setStyleSheet(
            "color: black;"
            "font-size: 30px;")

        self.mesenev_name = QLabel(self)
        self.mesenev_name.setFont(self.font)
        self.mesenev_name.setGeometry(590, 100, 900, 900)
        self.mesenev_name.setText('Неизвестен')
        self.mesenev_name.setStyleSheet(
            "color: black;"
            "font-size: 40px;")

        self.refresh()

        self.label = QLabel(self)
        self.label.setGeometry(355, -120, 400, 400)
        image_path1 = 'label.jpg'
        pixmap1 = QPixmap(image_path1)
        self.label.setPixmap(pixmap1)

    def exit_button(self):
        self.hide()
        main.show()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Return:
            self.send()
            self.refresh()

    def send(self):
        global current_user
        self.cur.execute('''INSERT INTO CHAT(USERNAME, MESSAGE) VALUES(?, ?)''',
                         (current_user, self.message_input.toPlainText()))
        self.con.commit()
        self.message_input.setText('')

    def refresh(self):
        result = self.cur.execute('''SELECT * FROM CHAT''')
        result = sorted(result, key=lambda x: x[0])
        for i in result:
            if i[2] not in self.message_pol.toPlainText():
                self.message_pol.append(f'  От: {i[1]}')
                self.message_pol.append(f'{i[2]}')
                self.message_pol.append('\n')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main = MainWindow()
    logs = Logs()
    settings = Settings()
    a = Authorization()
    a.show()
    c = CookieGraber()
    a.show()
    chat = Chat()
    sys.exit(app.exec())
