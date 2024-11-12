import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import datetime

class Database:
    def __init__(self, db_file):
        self.connection = sqlite3.connect(db_file)
        self.cursor = self.connection.cursor()

    def execute_query(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            self.connection.commit()
        except sqlite3.IntegrityError as e:
            messagebox.showerror("Database Error", f"An error occurred: {e}")

    def fetch_all(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {e}")
            return []

    def fetch_one(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            return self.cursor.fetchone()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {e}")
            return None

    def close(self):
        self.connection.close()

class DatabaseSetup:
    def __init__(self, db):
        self.connection = db.connection
        self.cursor = self.connection.cursor()
        self.db = db
        self.create_tables()
        

    def create_tables(self):
        self.db.execute_query("""
        CREATE TABLE IF NOT EXISTS Shelves (
            shelf_id INTEGER PRIMARY KEY AUTOINCREMENT,
            shelf_number INTEGER UNIQUE,
            description TEXT
        )
        """)
        self.db.execute_query("""
        CREATE TABLE IF NOT EXISTS Users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
        """)
        self.db.execute_query("""
        CREATE TABLE IF NOT EXISTS Materials (
            material_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            shelf_id INTEGER,
            material_type TEXT,
            purpose TEXT,
            date_registered TEXT,
            status TEXT,
            FOREIGN KEY (shelf_id) REFERENCES Shelves(shelf_id)
        )
        """)
        self.db.execute_query("""
        CREATE TABLE IF NOT EXISTS MaterialHistory (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER,
            change_date TEXT,
            change_description TEXT,
            FOREIGN KEY (material_id) REFERENCES Materials(material_id)
        )
        """)
    
        self.db.execute_query("""
        CREATE TABLE IF NOT EXISTS DeletedMaterials (
            material_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            shelf_id INTEGER,
            material_type TEXT,
            purpose TEXT,
            date_registered TEXT,
            status TEXT,
            date_deleted TEXT,
            FOREIGN KEY (shelf_id) REFERENCES Shelves(shelf_id)
        )
        """)


class User:
    def __init__(self, db, username, password):
        self.db = db
        self.username = username
        self.password = password
        self.role = None

    def login(self):
        query = "SELECT role FROM Users WHERE username = ? AND password = ?"
        result = self.db.fetch_all(query, (self.username, self.password))
        if result:
            self.role = result[0][0]
            return True
        return False

    def register(self, role):
        query = "INSERT INTO Users (username, password, role) VALUES (?, ?, ?)"
        try:
            self.db.execute_query(query, (self.username, self.password, role))
            return True
        except sqlite3.IntegrityError:
            return False

    def is_admin(self):
        return self.role == "admin"

    def is_worker(self):
        return self.role == "worker"

    def is_guest(self):
        return self.role == "guest"

class WarehouseApp:
    def __init__(self, root, db):
        self.root = root
        self.db = db
        self.db_setup = DatabaseSetup(self.db)
        self.show_login_screen()

    def show_login_screen(self):
        self.clear_window()
        login_window = tk.Frame(self.root)
        login_window.pack(pady=40)

        tk.Label(login_window, text="Вхід", font=("Arial", 32, "bold")).pack(pady=20)
        
        tk.Label(login_window, text="Ім'я користувача:", font=("Arial", 18)).pack(pady=10)
        self.login_username_entry = tk.Entry(login_window, font=("Arial", 18), width=40)
        self.login_username_entry.pack(pady=10)

        tk.Label(login_window, text="Пароль:", font=("Arial", 18)).pack(pady=10)
        self.login_password_entry = tk.Entry(login_window, show="*", font=("Arial", 18), width=40)
        self.login_password_entry.pack(pady=10)

        button_frame = tk.Frame(login_window)
        button_frame.pack(pady=30)

        tk.Button(button_frame, text="Вхід", font=("Arial", 18), command=self.login_user, width=15, height=2).grid(row=0, column=0, padx=20, pady=10)
        tk.Button(button_frame, text="Реєстрація", font=("Arial", 18), command=self.show_registration_screen, width=15, height=2).grid(row=0, column=1, padx=20, pady=10)

        self.root.geometry("900x800")

    def show_registration_screen(self):
        self.clear_window()
        registration_window = tk.Frame(self.root)
        registration_window.pack(pady=40)

        tk.Label(registration_window, text="Реєстрація", font=("Arial", 32, "bold")).pack(pady=20)

        tk.Label(registration_window, text="Ім'я користувача:", font=("Arial", 18)).pack(pady=10)
        self.reg_username_entry = tk.Entry(registration_window, font=("Arial", 18), width=40)
        self.reg_username_entry.pack(pady=10)

        tk.Label(registration_window, text="Пароль:", font=("Arial", 18)).pack(pady=10)
        self.reg_password_entry = tk.Entry(registration_window, show="*", font=("Arial", 18), width=40)
        self.reg_password_entry.pack(pady=10)

        tk.Label(registration_window, text="Роль:", font=("Arial", 18)).pack(pady=10)
        self.reg_role_combo = ttk.Combobox(registration_window, values=["Адміністратор", "Працівник", "Гість"], font=("Arial", 18), state="readonly", width=38)
        self.reg_role_combo.pack(pady=10)

        button_frame = tk.Frame(registration_window)
        button_frame.pack(pady=30)

        tk.Button(button_frame, text="Реєстрація", font=("Arial", 18), command=self.register_user, width=22, height=2).grid(row=0, column=0, padx=20, pady=10)
        tk.Button(button_frame, text="Повернутися до входу", font=("Arial", 18), command=self.show_login_screen, width=22, height=2).grid(row=0, column=1, padx=20, pady=10)

        self.root.geometry("900x800")
 
    def login_user(self):
        username = self.login_username_entry.get()
        password = self.login_password_entry.get()
        self.user = User(self.db, username, password)

        if self.user.login():
            messagebox.showinfo("Успішний вхід", f"Ласкаво просимо, {username}!")
            self.show_main_menu()
        else:
            messagebox.showerror("Невірні дані", "Невірне ім'я користувача або пароль.")

    def register_user(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        role = self.reg_role_combo.get()

        # Перетворення ролі з української в англійську для зберігання в базі даних
        role_map = {
            "Адміністратор": "admin",
            "Працівник": "worker",
            "Гість": "guest"
        }
        role = role_map.get(role)  # Отримуємо відповідне значення англійською

        if not username or not password or not role:
            messagebox.showerror("Реєстрація не вдалася", "Усі поля повинні бути заповнені.")
            return

        existing_user = self.db.fetch_one("SELECT * FROM Users WHERE username = ?", (username,))
        if existing_user:
            messagebox.showerror("Реєстрація не вдалася", "Ім'я користувача вже існує.")
            return

        self.user = User(self.db, username, password)
        if self.user.register(role):
            self.user.role = role  # Встановлення ролі після реєстрації
            messagebox.showinfo("Успішна реєстрація", "Користувача успішно зареєстровано!")
            self.show_login_screen()
        else:
            messagebox.showerror("Реєстрація не вдалася", "Сталася помилка під час реєстрації.")



    def show_main_menu(self):
        self.clear_window()
        main_frame = tk.Frame(self.root, padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)

        main_frame.grid_columnconfigure(0, weight=1, minsize=250)
        main_frame.grid_columnconfigure(1, weight=1, minsize=250)

        tk.Label(main_frame, text="Оберіть стелаж:", font=("Arial", 18)).grid(row=0, column=0, sticky="e", padx=10, pady=10)
        self.selected_shelf_id = None
        self.selected_shelf = tk.StringVar(value="Оберіть стелаж")
        self.shelf_dropdown = ttk.Combobox(main_frame, textvariable=self.selected_shelf, font=("Arial", 16), state="readonly", width=30)
        self.shelf_dropdown.grid(row=0, column=1, sticky="w", padx=10, pady=10)
        self.update_shelf_list()

        self.shelf_dropdown.bind("<<ComboboxSelected>>", self.set_selected_shelf)

        button_font = ("Arial", 16)
        button_width = 20

        tk.Button(main_frame, text="Додати стелаж", font=button_font, width=button_width, command=self.add_shelf).grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        tk.Button(main_frame, text="Додати матеріал", font=button_font, width=button_width, command=self.add_material).grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        tk.Button(main_frame, text="Переглянути всі матеріали", font=button_font, width=button_width, command=self.view_all_materials).grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        tk.Button(main_frame, text="Редагувати матеріал", font=button_font, width=button_width, command=self.edit_material).grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        tk.Button(main_frame, text="Шукати матеріал", font=button_font, width=button_width, command=self.search_material).grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        tk.Button(main_frame, text="Переглянути історію матеріалів", font=button_font, width=button_width, command=self.view_material_history).grid(row=3, column=1, padx=10, pady=10, sticky="ew")

        tk.Button(main_frame, text="Видалити стелаж", font=button_font, width=button_width, command=self.delete_shelf).grid(row=4, column=0, padx=10, pady=10, sticky="ew")
        tk.Button(main_frame, text="Видалити матеріал", font=button_font, width=button_width, command=self.delete_material).grid(row=4, column=1, padx=10, pady=10, sticky="ew")

        tk.Button(main_frame, text="Переглянути видалені матеріали", font=button_font, width=button_width, command=self.view_deleted_materials).grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        tk.Button(main_frame, text="Вийти з акаунту", font=button_font, width=button_width, command=self.show_login_screen).grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        self.root.geometry("1100x800")



    def add_shelf(self):
        if not (self.user.is_admin()):
            messagebox.showwarning("Доступ заборонено", "Ця функція доступна лише для адміністратора.")
            return
        add_shelf_window = tk.Toplevel(self.root)
        add_shelf_window.title("Додати стелаж")
        add_shelf_window.geometry("600x450")  

        main_frame = tk.Frame(add_shelf_window, padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(main_frame, text="Назва стелажу:", font=("Arial", 14)).pack(pady=10)
        
        shelf_name_entry = tk.Entry(main_frame, font=("Arial", 12), width=30)
        shelf_name_entry.pack(pady=10)

        def submit_shelf():
            shelf_name = shelf_name_entry.get()
            try:
                self.db.execute_query("INSERT INTO Shelves (description) VALUES (?)", (shelf_name,))
                messagebox.showinfo("Успіх", "Стелаж додано успішно!")
                self.update_shelf_list()
                add_shelf_window.destroy()
            except sqlite3.IntegrityError:
                messagebox.showerror("Помилка", "Стелаж з такою назвою вже існує.")

        tk.Button(main_frame, text="Підтвердити", command=submit_shelf, font=("Arial", 14), width=15).pack(pady=20)



    def select_shelf(self):
        select_shelf_window = tk.Toplevel(self.root)
        select_shelf_window.title("Вибір стелажу")

        shelves = self.db.fetch_all("SELECT shelf_id, shelf_number FROM Shelves")
        shelf_options = [f"Стелаж {shelf[1]}" for shelf in shelves]
        selected_shelf = tk.StringVar()
        selected_shelf.set(shelf_options[0])  

        tk.Label(select_shelf_window, text="Оберіть стелаж:").pack()
        tk.OptionMenu(select_shelf_window, selected_shelf, *shelf_options).pack()

        tk.Button(select_shelf_window, text="Оберіть", command=lambda: self.set_selected_shelf(selected_shelf.get())).pack()

    def delete_shelf(self):
        if not (self.user.is_admin()):
            messagebox.showwarning("Доступ заборонено", "Ця функція доступна лише для адміністратора")
            return
        if self.selected_shelf_id is None:
            messagebox.showwarning("Не обрано стелаж", "Будь ласка, оберіть стелаж для видалення.")
            return

        confirm = messagebox.askyesno("Підтвердження видалення", "Ви впевнені, що хочете видалити цей стелаж та всі матеріали на ньому?")
        if confirm:
            self.db.execute_query("DELETE FROM Materials WHERE shelf_id = ?", (self.selected_shelf_id,))
            self.db.execute_query("DELETE FROM Shelves WHERE shelf_id = ?", (self.selected_shelf_id,))
            self.update_shelf_list()
            self.selected_shelf_id = None
            messagebox.showinfo("Успіх", "Стелаж та його матеріали видалено успішно.")

            

    def update_shelf_list(self):
        shelves = self.db.fetch_all("SELECT shelf_id, description FROM Shelves")
        self.shelf_options = [shelf[1] for shelf in shelves]
        self.shelf_dropdown['values'] = self.shelf_options


    def set_selected_shelf(self, event):
        shelf_name = self.selected_shelf.get()
        result = self.db.fetch_one("SELECT shelf_id FROM Shelves WHERE description = ?", (shelf_name,))
        self.selected_shelf_id = result[0] if result else None
        messagebox.showinfo("Shelf Selected", f"Selected Shelf: {shelf_name}")

    def add_material(self):
        if not (self.user.is_admin() or self.user.is_worker()):
            messagebox.showwarning("Доступ заборонено", "Ця функція доступна лише для працівників складу")
            return
        if self.selected_shelf_id is None:
            messagebox.showwarning("Не обраний стелаж", "Будь ласка, оберіть стелаж перед додаванням матеріалу.")
            return

        add_material_window = tk.Toplevel(self.root)
        add_material_window.title("Додати матеріал")
        add_material_window.geometry("800x700")

        main_frame = tk.Frame(add_material_window, padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)

        main_frame.grid_columnconfigure(0, weight=1, minsize=200)
        main_frame.grid_columnconfigure(1, weight=1, minsize=300)

        tk.Label(main_frame, text="Назва матеріалу:", font=("Arial", 12)).grid(row=0, column=0, sticky="e", pady=10)
        name_entry = tk.Entry(main_frame, font=("Arial", 12), width=30)
        name_entry.grid(row=0, column=1, sticky="w", pady=10)

        tk.Label(main_frame, text="Тип матеріалу:", font=("Arial", 12)).grid(row=1, column=0, sticky="e", pady=10)
        type_entry = tk.Entry(main_frame, font=("Arial", 12), width=30)
        type_entry.grid(row=1, column=1, sticky="w", pady=10)

        tk.Label(main_frame, text="Призначення:", font=("Arial", 12)).grid(row=2, column=0, sticky="e", pady=10)
        purpose_entry = tk.Entry(main_frame, font=("Arial", 12), width=30)
        purpose_entry.grid(row=2, column=1, sticky="w", pady=10)

        tk.Label(main_frame, text="Статус:", font=("Arial", 12)).grid(row=3, column=0, sticky="e", pady=10)
        status_options = ["Новий", "Використовується", "Зберігається", "Пошкоджено", "Прострочений", "Зарезервований", "На перевірці", "Утилізований"]
        status_entry = ttk.Combobox(main_frame, values=status_options, font=("Arial", 12), state="readonly")
        status_entry.set(status_options[0])
        status_entry.grid(row=3, column=1, sticky="w", pady=10)

        def submit_material():
            material_name = name_entry.get()
            material_type = type_entry.get()
            material_purpose = purpose_entry.get()
            material_status = status_entry.get()
            date_registered = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if not material_name or not material_type or not material_purpose:
                messagebox.showwarning("Відсутні дані", "Будь ласка, заповніть усі поля.")
                return

            try:
                self.db.execute_query(""" 
                    INSERT INTO Materials (name, shelf_id, material_type, purpose, date_registered, status) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (material_name, self.selected_shelf_id, material_type, material_purpose, date_registered, material_status))

                messagebox.showinfo("Успіх", "Матеріал успішно додано!")
                add_material_window.destroy()
            except sqlite3.Error as e:
                messagebox.showerror("Помилка", f"Не вдалося додати матеріал: {e}")

        submit_button = tk.Button(main_frame, text="Додати", font=("Arial", 12), command=submit_material)
        submit_button.grid(row=4, column=0, columnspan=2, pady=20, sticky="ew")

        close_button = tk.Button(main_frame, text="Закрити", font=("Arial", 12), command=add_material_window.destroy)
        close_button.grid(row=5, column=0, columnspan=2, pady=20, sticky="ew")


    def delete_material(self):
        if not (self.user.is_admin() or self.user.is_worker()):
            messagebox.showwarning("Доступ заборонено", "Ця функція доступна лише для працівників складу")
            return
        if self.selected_shelf_id is None:
            messagebox.showwarning("Не обрано стелаж", "Будь ласка, спочатку оберіть стелаж.")
            return

        materials = self.db.fetch_all("SELECT material_id, name FROM Materials WHERE shelf_id = ?", (self.selected_shelf_id,))
        if not materials:
            messagebox.showwarning("Немає матеріалів", "На обраному стелажі немає матеріалів.")
            return

        material_options = [f"{m[1]} (ID: {m[0]})" for m in materials]

        select_window = tk.Toplevel(self.root)
        select_window.title("Видалення матеріалу")
        select_window.geometry("800x700")  # Нові розміри вікна

        main_frame = tk.Frame(select_window, padx=40, pady=40)  # Розширені відступи
        main_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(main_frame, text="Оберіть матеріал для видалення:", font=("Arial", 14)).grid(row=0, column=0, columnspan=2, pady=20)

        material_var = tk.StringVar()
        material_dropdown = ttk.Combobox(main_frame, textvariable=material_var, values=material_options, state="readonly", font=("Arial", 12))
        material_dropdown.grid(row=1, column=0, columnspan=2, pady=20, sticky="ew")

        def submit_deletion():
            selected_material = material_var.get()
            if not selected_material:
                messagebox.showwarning("Не обрано", "Будь ласка, оберіть матеріал для видалення.")
                return

            material_id = int(selected_material.split(" (ID: ")[1][:-1])

            try:
                material = self.db.fetch_one("SELECT * FROM Materials WHERE material_id = ?", (material_id,))
                self.db.execute_query("""
                    INSERT INTO DeletedMaterials (material_id, name, shelf_id, material_type, purpose, date_registered, status, date_deleted)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, material)

                self.db.execute_query("DELETE FROM Materials WHERE material_id = ?", (material_id,))
                messagebox.showinfo("Успіх", "Матеріал успішно видалено!")
                select_window.destroy()
            except sqlite3.Error as e:
                messagebox.showerror("Помилка", f"Не вдалося видалити матеріал: {e}")

        submit_button = tk.Button(main_frame, text="Видалити", command=submit_deletion, font=("Arial", 12))
        submit_button.grid(row=2, column=0, padx=20, pady=40)

        cancel_button = tk.Button(main_frame, text="Скасувати", command=select_window.destroy, font=("Arial", 12))
        cancel_button.grid(row=2, column=1, padx=20, pady=40)

        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)




    def view_all_materials(self):
        if not self.selected_shelf_id:
            messagebox.showerror("Помилка вибору", "Будь ласка, спочатку виберіть стелаж.")
            return

        materials = self.db.fetch_all(""" 
            SELECT material_id, name, material_type, purpose, date_registered, status 
            FROM Materials WHERE shelf_id = ?
        """, (self.selected_shelf_id,))

        view_window = tk.Toplevel(self.root)
        view_window.title("Матеріали на обраному стелажі")
        view_window.geometry("900x800")  

        main_frame = tk.Frame(view_window, padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ID", "Назва", "Тип", "Призначення", "Дата реєстрації", "Статус")
        treeview = ttk.Treeview(main_frame, columns=columns, show="headings", selectmode="browse", height=20)
        
        for col in columns:
            treeview.heading(col, text=col, anchor="center")
            treeview.column(col, width=120, anchor="center")
        
        for material in materials:
            treeview.insert("", tk.END, values=material)

        treeview.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=treeview.yview)
        treeview.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        close_button = tk.Button(view_window, text="Закрити", command=view_window.destroy, font=("Arial", 12))
        close_button.pack(pady=20)


    def view_deleted_materials(self):
        if not (self.user.is_admin()):
            messagebox.showwarning("Доступ заборонено", "Ця функція доступна лише для адміністратора")
            return
        if self.selected_shelf_id is None:
            messagebox.showwarning("Не обрано стелаж", "Будь ласка, виберіть стелаж для перегляду видалених матеріалів.")
            return

        deleted_materials = self.db.fetch_all("""
            SELECT name, material_type, purpose, date_registered, status, date_deleted
            FROM DeletedMaterials WHERE shelf_id = ?
        """, (self.selected_shelf_id,))

        if not deleted_materials:
            messagebox.showinfo("Видалені матеріали відсутні", "Для цього стелажа немає видалених матеріалів.")
            return

        view_window = tk.Toplevel(self.root)
        view_window.title("Видалені матеріали")
        view_window.geometry("900x800")  

        main_frame = tk.Frame(view_window, padx=30, pady=30)
        main_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Назва", "Тип", "Призначення", "Дата реєстрації", "Статус", "Дата видалення")
        treeview = ttk.Treeview(main_frame, columns=columns, show="headings", selectmode="browse", height=20)
        
        for col in columns:
            treeview.heading(col, text=col, anchor="center")
            treeview.column(col, width=120, anchor="center")

        for material in deleted_materials:
            treeview.insert("", tk.END, values=material)

        treeview.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=treeview.yview)
        treeview.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        close_button = tk.Button(view_window, text="Закрити", command=view_window.destroy, font=("Arial", 12))
        close_button.pack(pady=20)

        
    def edit_material(self):
        if not (self.user.is_admin() or self.user.is_worker()):
            messagebox.showwarning("Доступ заборонено", "Ця функція доступна лише для працівників складу")
            return
        if not self.selected_shelf_id:
            messagebox.showerror("Помилка вибору", "Будь ласка, спочатку виберіть стелаж.")
            return

        materials = self.db.fetch_all("""
            SELECT material_id, name FROM Materials WHERE shelf_id = ?
        """, (self.selected_shelf_id,))

        edit_material_window = tk.Toplevel(self.root)
        edit_material_window.title("Редагування матеріалу")
        edit_material_window.geometry("1000x600") 

        main_frame = tk.Frame(edit_material_window, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ID", "Назва")
        treeview = ttk.Treeview(main_frame, columns=columns, show="headings", selectmode="browse")

        for col in columns:
            treeview.heading(col, text=col)
            treeview.column(col, width=150, anchor="center")

        for material in materials:
            treeview.insert("", tk.END, values=material)

        treeview.pack(fill=tk.BOTH, expand=True, pady=10)

        tk.Label(edit_material_window, text="Нова назва:").pack(pady=5)
        new_name_entry = tk.Entry(edit_material_window)
        new_name_entry.pack()

        tk.Label(edit_material_window, text="Новий тип:").pack(pady=5)
        new_type_entry = tk.Entry(edit_material_window)
        new_type_entry.pack()

        tk.Label(edit_material_window, text="Нове призначення:").pack(pady=5)
        new_purpose_entry = tk.Entry(edit_material_window)
        new_purpose_entry.pack()

        tk.Label(edit_material_window, text="Новий статус:").pack(pady=5)
        status_options = ["Новий", "Використовується", "Зберігається", "Пошкоджений", "Прострочений", "Зарезервований", "На перевірці", "Утилізований"]
        new_status_combo = ttk.Combobox(edit_material_window, values=status_options)
        new_status_combo.pack()

        def load_material_details():
            selected_item = treeview.selection()
            if not selected_item:
                messagebox.showerror("Помилка вибору", "Будь ласка, виберіть матеріал для завантаження деталей.")
                return

            material_id = treeview.item(selected_item)["values"][0]
            material = self.db.fetch_one("""
                SELECT name, material_type, purpose, status 
                FROM Materials WHERE material_id = ?
            """, (material_id,))

            new_name_entry.delete(0, tk.END)
            new_name_entry.insert(0, material[0])

            new_type_entry.delete(0, tk.END)
            new_type_entry.insert(0, material[1])

            new_purpose_entry.delete(0, tk.END)
            new_purpose_entry.insert(0, material[2])

            new_status_combo.set(material[3])

        load_button_frame = tk.Frame(edit_material_window)
        load_button_frame.pack(pady=10)

        tk.Button(load_button_frame, text="Завантажити деталі матеріалу", command=load_material_details).pack(side=tk.LEFT, padx=10)

        def submit_edit():
            selected_item = treeview.selection()
            if not selected_item:
                messagebox.showerror("Помилка вибору", "Будь ласка, виберіть матеріал для редагування.")
                return

            material_id = treeview.item(selected_item)["values"][0]
            new_name = new_name_entry.get()
            new_type = new_type_entry.get()
            new_purpose = new_purpose_entry.get()
            new_status = new_status_combo.get()

            try:
                self.db.execute_query("""
                    UPDATE Materials SET name = COALESCE(?, name),
                                        material_type = COALESCE(?, material_type),
                                        purpose = COALESCE(?, purpose),
                                        status = COALESCE(?, status)
                    WHERE material_id = ?
                """, (new_name, new_type, new_purpose, new_status, material_id))

                change_description = f"Оновлено деталі матеріалу: Назва: {new_name}, Тип: {new_type}, Призначення: {new_purpose}, Статус: {new_status}"
                self.db.execute_query("""
                    INSERT INTO MaterialHistory (material_id, change_date, change_description)
                    VALUES (?, CURRENT_TIMESTAMP, ?)
                """, (material_id, change_description))

                messagebox.showinfo("Успіх", "Матеріал успішно оновлено!")
                edit_material_window.destroy()
            except sqlite3.Error as e:
                messagebox.showerror("Помилка", f"Не вдалося редагувати матеріал: {e}")

        tk.Button(edit_material_window, text="Підтвердити зміни", command=submit_edit).pack(pady=10)



    def update_material_list(self, material_dropdown):
            materials = self.db.fetch_all("SELECT material_id, name FROM Materials")
            material_options = [f"{material[0]} {material[1]}" for material in materials]
            material_dropdown['values'] = material_options



    def search_material(self):
        def submit_search():
            keyword = keyword_entry.get()
            selected_status = status_combo.get()

            query = "SELECT material_id, name, material_type, purpose, date_registered, status FROM Materials WHERE 1=1"
            params = []

            if keyword:
                query += " AND (name LIKE ? OR material_type LIKE ?)"
                params.extend([f'%{keyword}%', f'%{keyword}%'])

            if selected_status:
                query += " AND status = ?"
                params.append(selected_status)

            results = self.db.fetch_all(query, tuple(params))

            results_window = tk.Toplevel(self.root)
            results_window.title("Результати пошуку")
            results_window.geometry("1000x600") 

            if not results:
                tk.Label(results_window, text="Матеріали, що відповідають критеріям, не знайдені.").pack(pady=20)
            else:
                columns = ("ID", "Назва", "Тип", "Призначення", "Дата реєстрації", "Статус")
                treeview = ttk.Treeview(results_window, columns=columns, show="headings")

                for col in columns:
                    treeview.heading(col, text=col)
                    treeview.column(col, width=150, anchor="center")

                for row in results:
                    treeview.insert("", tk.END, values=row)

                treeview.pack(fill=tk.BOTH, expand=True, pady=10)

        search_window = tk.Toplevel(self.root)
        search_window.title("Пошук матеріалу")
        search_window.geometry("400x300")  

        tk.Label(search_window, text="Введіть ключове слово (необов'язково):").pack(pady=10)
        keyword_entry = tk.Entry(search_window)
        keyword_entry.pack(pady=5)

        tk.Label(search_window, text="Оберіть статус (необов'язково):").pack(pady=10)
        status_combo = ttk.Combobox(search_window, values=["", "Новий", "Використовується", "Зберігається", "Пошкоджений", "Прострочений", "Зарезервований", "На перевірці", "Утилізований"])
        status_combo.set("")  
        status_combo.pack(pady=5)

        tk.Button(search_window, text="Пошук", command=submit_search).pack(pady=20)


    def view_material_history(self):
        if not (self.user.is_admin()):
            messagebox.showwarning("Доступ заборонено", "Ця функція доступна лише для адміністратора")
            return
        if self.selected_shelf_id is None:
            messagebox.showwarning("Стелаж не вибрано", "Будь ласка, оберіть стелаж перед переглядом історії матеріалу.")
            return

        materials = self.db.fetch_all("SELECT material_id, name FROM Materials WHERE shelf_id = ?", (self.selected_shelf_id,))
        if not materials:
            messagebox.showinfo("Немає матеріалів", "У вибраному стелажі немає матеріалів.")
            return

        view_history_window = tk.Toplevel(self.root)
        view_history_window.title("Історія матеріалу")
        view_history_window.geometry("900x800")

        main_frame = tk.Frame(view_history_window, padx=30, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(main_frame, text="Оберіть матеріал:", font=("Arial", 12)).pack(pady=5)
        material_options = [f"{material[1]}" for material in materials]
        selected_material = tk.StringVar(value=material_options[0])
        material_dropdown = ttk.Combobox(main_frame, textvariable=selected_material, values=material_options, state="readonly", font=("Arial", 11))
        material_dropdown.pack(pady=5)

        def show_history():
            material_name = selected_material.get()
            material_id = next(material[0] for material in materials if material[1] == material_name)

            history = self.db.fetch_all("SELECT change_date, change_description FROM MaterialHistory WHERE material_id = ?", (material_id,))
            if not history:
                messagebox.showinfo("Немає історії", f"Для матеріалу {material_name} немає історії.")
                return

            history_window = tk.Toplevel(self.root)
            history_window.title(f"Історія для {material_name}")
            history_window.geometry("1200x800")

            history_frame = tk.Frame(history_window, padx=20, pady=20)
            history_frame.pack(fill=tk.BOTH, expand=True)

            columns = ("Дата", "Опис змін")
            treeview = ttk.Treeview(history_frame, columns=columns, show="headings", height=25)
            
            for col in columns:
                treeview.heading(col, text=col, anchor="center")
                treeview.column(col, width=400 if col == "Опис змін" else 150, anchor="center")
            
            for change in history:
                treeview.insert("", tk.END, values=change)

            treeview.pack(fill=tk.BOTH, expand=True, pady=10)

            scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=treeview.yview)
            treeview.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            close_button = tk.Button(history_window, text="Закрити", command=history_window.destroy, font=("Arial", 12))
            close_button.pack(pady=20)

        tk.Button(main_frame, text="Показати історію", command=show_history, font=("Arial", 12)).pack(pady=20)




    def clear_window(self):
            for widget in self.root.winfo_children():
                widget.destroy()

def main():
    root = tk.Tk()  
    root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Warehouse Management System")
    db = Database("warehouse.db")  
    app = WarehouseApp(root, db)  
    root.mainloop()  
