package main

import (
	"database/sql" // Импортируем пакет для работы с базами данных
	"fmt"          // Импортируем пакет для форматирования строк
	"html/template" // Импортируем пакет для работы с HTML-шаблонами
	"log"          // Импортируем пакет для логирования ошибок
	"net/http"     // Импортируем пакет для работы с HTTP
	"strconv"      // Импортируем пакет для преобразования строк в числа
	"time"         // Импортируем пакет для работы с временем

	_ "github.com/mattn/go-sqlite3" // Импортируем драйвер SQLite
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB // Глобальная переменная для подключения к базе данных

// User структура для хранения пользовательских данных
type User struct {
	ID       int
	Name     string
	Email    string
	Password string
	Phone    string
	IsAdmin  bool
}

// Product структура для хранения данных о продукте
type Product struct {
	ID   int
	Name string
	Kind string
	Type string
	Cost float64
}

// Order структура для хранения данных о заказе
type Order struct {
	ID            int
	UserID        int
	UserName      string
	Items         []Product
	Total         float64
	Status        string
	DateTime      time.Time
	Address       string
	PaymentMethod string
}

// CartItem структура для хранения данных о товаре в корзине
type CartItem struct {
	ID       int     // Идентификатор элемента корзины
	UserID   int     // Идентификатор пользователя
	Product  Product // Продукт в корзине
	Quantity int // Количество продукта в корзине
}

// Инициализируйте подключение к базе данных
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./shop.db") // Открываем соединение с базой данных
	if err != nil {
		log.Fatal(err) //логируем ошибку
	}

	// Инициализируйте таблицы, если они не существуют
	initTables() // Инициализируем таблицы в базе данных

	// Инициализация данных по умолчанию
	initDefaultData() // Заполняем базу данных начальными данными
}

// Инициализация таблиц
func initTables() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		phone TEXT NOT NULL,
		is_admin BOOLEAN NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		kind TEXT NOT NULL,
		type TEXT NOT NULL,
		cost REAL NOT NULL
	);

	CREATE TABLE IF NOT EXISTS orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		total REAL NOT NULL,
		status TEXT NOT NULL,
		datetime DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS order_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_id INTEGER NOT NULL,
		product_id INTEGER NOT NULL,
		quantity INTEGER NOT NULL,
		FOREIGN KEY (order_id) REFERENCES orders(id),
		FOREIGN KEY (product_id) REFERENCES products(id)
	);

	CREATE TABLE IF NOT EXISTS cart (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		product_id INTEGER NOT NULL,
		quantity INTEGER DEFAULT 1,
		FOREIGN KEY (user_id) REFERENCES users(id),
		FOREIGN KEY (product_id) REFERENCES products(id)
	);`

	_, err := db.Exec(query) //запрос на создание таблиц
	if err != nil {
		log.Fatal(err) // Логируем ошибку
	}
}

// Инициализация данных по умолчанию

// функция initDefaultData проверяет, есть ли уже продукты в базе данных,
// и если нет, добавляет 20 товаров по умолчанию. 
func initDefaultData() {
	// Check if products already exist
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM products").Scan(&count) // Проверяем, есть ли уже продукты
	if err != nil {
		log.Fatal(err)
	}

	if count == 0 {
		// Вставка товаров по умолчанию
		for i := 1; i <= 20; i++ {
			_, err := db.Exec("INSERT INTO products (name, kind, type, cost) VALUES (?, ?, ?, ?)",
				fmt.Sprintf("Краска №%d", i), "Краска для стен", "Матовая", float64(100+i*10)) // Вставляем продукты по умолчанию
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}






















// Хэширование пароля с солью
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14) // Генерируем хэш пароля с использованием bcrypt
	return string(bytes), err // Возвращаем хэшированный пароль и ошибку (если есть)
}

// Сравните хэша с предоставленным паролем
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) // Сравниваем хэшированный пароль с введенным
	return err == nil // Возвращаем true, если пароли совпадают, иначе false
}

// Средство визуализации шаблонов
func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	tmplPath := fmt.Sprintf("templates/%s.html", tmpl)
	t, err := template.ParseFiles(tmplPath)
	if err != nil {
		log.Printf("Ошибка загрузки шаблона: %s, путь: %s, ошибка: %v", tmpl, tmplPath, err)
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

// Получение текущего пользователя из файла cookie
func getCurrentUser(r *http.Request) (*User, error) {
	cookie, err := r.Cookie("user_id")
	if err != nil {
		return nil, err
	}

	userID, err := strconv.Atoi(cookie.Value)
	if err != nil {
		return nil, err
	}

	var user User
	err = db.QueryRow("SELECT id, name, email, phone, is_admin FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.Name, &user.Email, &user.Phone, &user.IsAdmin)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Обработчики

// Обработчик домашней страницы
func homeHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "index", user)
}

// Обработчик регистрации
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		name := r.FormValue("name")
		email := r.FormValue("email")
		phone := r.FormValue("phone")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		if password != confirmPassword {
			http.Error(w, "Пароли не совпадают", http.StatusBadRequest)
			return
		}

		hashedPassword, err := hashPassword(password)
		if err != nil {
			http.Error(w, "Ошибка при хэшировании пароля", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)",
			name, email, phone, hashedPassword)
		if err != nil {
			http.Error(w, "Пользователь уже существует или ошибка базы данных", http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	renderTemplate(w, "register", nil)
}
















// Обработчик входа в систему
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var storedPassword string
		var userID int
		var isAdmin bool
		err := db.QueryRow("SELECT id, password, is_admin FROM users WHERE email = ?", email).
			Scan(&userID, &storedPassword, &isAdmin)
		if err != nil || !checkPasswordHash(password, storedPassword) {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			return
		}

		// Формирование cookie-файла
		http.SetCookie(w, &http.Cookie{
			Name:  "user_id",
			Value: strconv.Itoa(userID),
			Path:  "/",
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	renderTemplate(w, "login", nil)
}

// Обработчик выхода из системы
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Очищение cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "user_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
 // Обработчик страницы профиля
func profileHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	rows, err := db.Query("SELECT id, total, status, datetime, address, payment_method FROM orders WHERE user_id = ?", user.ID)
	if err != nil {
		http.Error(w, "Ошибка при получении заказов", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var order Order
		err = rows.Scan(&order.ID, &order.Total, &order.Status, &order.DateTime, &order.Address, &order.PaymentMethod)
		if err != nil {
			http.Error(w, "Ошибка при обработке заказа", http.StatusInternalServerError)
			return
		}

		productRows, err := db.Query(`
            SELECT p.id, p.name, p.kind, p.type, p.cost
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?`, order.ID)
		if err != nil {
			http.Error(w, "Ошибка при получении товаров заказа", http.StatusInternalServerError)
			return
		}

		var products []Product
		for productRows.Next() {
			var product Product
			err = productRows.Scan(&product.ID, &product.Name, &product.Kind, &product.Type, &product.Cost)
			if err != nil {
				productRows.Close() // Закрываем в случае ошибки
				http.Error(w, "Ошибка при обработке товара", http.StatusInternalServerError)
				return
			}
			products = append(products, product)
		}
		productRows.Close()

		// Связываем товары с заказом
		order.Items = products
		orders = append(orders, order)
	}

	data := struct {
		User   *User
		Orders []Order
	}{
		User:   user,
		Orders: orders,
	}

	renderTemplate(w, "profile", data)
}

// Обработчик обновления статуса заказа
func updateOrderStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	user, err := getCurrentUser(r)
	if err != nil || !user.IsAdmin {
		http.Error(w, "Нет доступа", http.StatusForbidden)
		return
	}

	orderID := r.FormValue("order_id")
	newStatus := r.FormValue("status")

	if orderID == "" || newStatus == "" {
		http.Error(w, "Неверные данные", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE orders SET status = ? WHERE id = ?", newStatus, orderID)
	if err != nil {
		http.Error(w, "Ошибка при обновлении статуса заказа", http.StatusInternalServerError)
		return
	}

	// Перенаправляем обратно на страницу админки
	http.Redirect(w, r, "/admin/orders", http.StatusSeeOther)
}

// Обработчик каталога товаров
func catalogHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем список товаров
	rows, err := db.Query("SELECT id, name, kind, type, cost FROM products")
	if err != nil {
		http.Error(w, "Ошибка при получении каталога", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	products := []Product{}
	for rows.Next() {
		var product Product
		err = rows.Scan(&product.ID, &product.Name, &product.Kind, &product.Type, &product.Cost)
		if err != nil {
			http.Error(w, "Ошибка при обработке продукта", http.StatusInternalServerError)
			return
		}
		products = append(products, product)
	}

	user, _ := getCurrentUser(r)
	data := struct {
		User     *User
		Products []Product
	}{
		User:     user,
		Products: products,
	}

	renderTemplate(w, "catalog", data)
}

// Обработчик админской панели
func adminPanelHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil || !user.IsAdmin {
		http.Error(w, "Нет доступа", http.StatusForbidden)
		return
	}

	renderTemplate(w, "admin", user)
}

// Обработчик управления заказами администратором
func adminOrdersHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil || !user.IsAdmin {
		http.Error(w, "Нет доступа", http.StatusForbidden)
		return
	}

	rows, err := db.Query(`
        SELECT o.id, o.user_id, u.name, o.total, o.status, o.datetime, o.address, o.payment_method
        FROM orders o
        JOIN users u ON o.user_id = u.id`)
	if err != nil {
		http.Error(w, "Ошибка при получении заказов", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var order Order
		err = rows.Scan(&order.ID, &order.UserID, &order.UserName, &order.Total, &order.Status, &order.DateTime, &order.Address, &order.PaymentMethod)
		if err != nil {
			http.Error(w, "Ошибка при обработке заказа", http.StatusInternalServerError)
			return
		}

		productRows, err := db.Query(`
            SELECT p.id, p.name, p.kind, p.type, p.cost
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?`, order.ID)
		if err != nil {
			http.Error(w, "Ошибка при получении товаров заказа", http.StatusInternalServerError)
			return
		}
		defer productRows.Close()

		var products []Product
		for productRows.Next() {
			var product Product
			err = productRows.Scan(&product.ID, &product.Name, &product.Kind, &product.Type, &product.Cost)
			if err != nil {
				http.Error(w, "Ошибка при обработке товара", http.StatusInternalServerError)
				return
			}
			products = append(products, product)
		}

		order.Items = products
		orders = append(orders, order)
	}

	data := struct {
		User   *User
		Orders []Order
	}{
		User:   user,
		Orders: orders,
	}

	renderTemplate(w, "admin_orders", data)
}


// Обработчик добавления в корзину
func addToCartHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/catalog", http.StatusSeeOther)
		return
	}

	user, err := getCurrentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	productIDStr := r.FormValue("product_id")
	productID, err := strconv.Atoi(productIDStr)
	if err != nil {
		http.Error(w, "Неверный ID продукта", http.StatusBadRequest)
		return
	}

	// Проверка существования продуктов
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM products WHERE id = ?)", productID).Scan(&exists)
	if err != nil || !exists {
		http.Error(w, "Продукт не найден", http.StatusNotFound)
		return
	}

	// Проверка есть ли этот товар уже в корзине
	var cartID int
	var quantity int
	err = db.QueryRow("SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?", user.ID, productID).Scan(&cartID, &quantity)
	if err != nil {
		if err == sql.ErrNoRows {
			// Добавление нового товар в корзину
			_, err := db.Exec("INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)", user.ID, productID, 1)
			if err != nil {
				http.Error(w, "Ошибка при добавлении в корзину", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "Ошибка базы данных", http.StatusInternalServerError)
			return
		}
	} else {
		// Увеличение количества товара, если он уже есть в корзине
		_, err := db.Exec("UPDATE cart SET quantity = ? WHERE id = ?", quantity+1, cartID)
		if err != nil {
			http.Error(w, "Ошибка при обновлении корзины", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

// Переключить обработчик администратора
func toggleAdminHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil || !user.IsAdmin {
		http.Error(w, "Нет доступа", http.StatusForbidden)
		return
	}

	userIDStr := r.FormValue("user_id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Неверный ID пользователя", http.StatusBadRequest)
		return
	}

	// Получение текущего статуса администратора
	var isAdmin bool
	err = db.QueryRow("SELECT is_admin FROM users WHERE id = ?", userID).Scan(&isAdmin)
	if err != nil {
		http.Error(w, "Ошибка при получении данных пользователя", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// Обработчик корзины
func cartHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Выборка товаров из корзины
	rows, err := db.Query(`
        SELECT c.id, c.product_id, p.name, p.kind, p.type, p.cost, c.quantity
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?`, user.ID)
	if err != nil {
		http.Error(w, "Ошибка при получении корзины", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	cartItems := []CartItem{}
	var total float64
	for rows.Next() {
		var item CartItem
		var product Product
		err = rows.Scan(&item.ID, &item.Product.ID, &product.Name, &product.Kind, &product.Type, &product.Cost, &item.Quantity)
		if err != nil {
			http.Error(w, "Ошибка при обработке корзины", http.StatusInternalServerError)
			return
		}
		item.Product = product
		cartItems = append(cartItems, item)
		total += product.Cost * float64(item.Quantity)
	}

	data := struct {
		CartItems []CartItem
		Total     float64
	}{
		CartItems: cartItems,
		Total:     total,
	}

	renderTemplate(w, "cart", data)
}

// Обработчик удаления товара из корзины
func removeFromCartHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	cartItemIDStr := r.FormValue("cart_item_id")
	cartItemID, err := strconv.Atoi(cartItemIDStr)
	if err != nil {
		http.Error(w, "Неверный ID товара в корзине", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("DELETE FROM cart WHERE id = ? AND user_id = ?", cartItemID, user.ID)
	if err != nil {
		http.Error(w, "Ошибка при удалении товара из корзины", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

// Обработчик оформления заказа
func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/cart", http.StatusSeeOther)
		return
	}

	user, err := getCurrentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Получение данных из формы
	address := r.FormValue("address")
	paymentMethod := r.FormValue("payment")

	if address == "" || paymentMethod == "" {
		http.Error(w, "Не указаны все данные для оформления заказа", http.StatusBadRequest)
		return
	}

	// Получение товаров из корзины пользователя
	rows, err := db.Query(`
		SELECT c.id, c.product_id, p.name, p.kind, p.type, p.cost, c.quantity
		FROM cart c
		JOIN products p ON c.product_id = p.id
		WHERE c.user_id = ?`, user.ID)
	if err != nil {
		http.Error(w, "Ошибка при получении корзины", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	cartItems := []CartItem{}
	var total float64
	for rows.Next() {
		var item CartItem
		var product Product
		err = rows.Scan(&item.ID, &item.Product.ID, &product.Name, &product.Kind, &product.Type, &product.Cost, &item.Quantity)
		if err != nil {
			http.Error(w, "Ошибка при обработке корзины", http.StatusInternalServerError)
			return
		}
		item.Product = product
		cartItems = append(cartItems, item)
		total += product.Cost * float64(item.Quantity)
	}

	// Создание заказа
	result, err := db.Exec("INSERT INTO orders (user_id, total, status, datetime, address, payment_method) VALUES (?, ?, ?, ?, ?, ?)",
		user.ID, total, "На рассмотрении", time.Now(), address, paymentMethod)
	if err != nil {
		http.Error(w, "Ошибка при создании заказа", http.StatusInternalServerError)
		return
	}

	orderID, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "Ошибка при создании заказа", http.StatusInternalServerError)
		return
	}

	// Добавление товаров в таблицу order_items
	for _, item := range cartItems {
		_, err := db.Exec("INSERT INTO order_items (order_id, product_id, quantity) VALUES (?, ?, ?)",
			orderID, item.Product.ID, item.Quantity)
		if err != nil {
			http.Error(w, "Ошибка при добавлении товаров в заказ", http.StatusInternalServerError)
			return
		}
	}

	// Очистка корзины пользователя
	_, err = db.Exec("DELETE FROM cart WHERE user_id = ?", user.ID)
	if err != nil {
		http.Error(w, "Ошибка при очистке корзины", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func main() {
	// Инициализация базы данных
	initDB()
	defer db.Close()

	// Обрбаботчики
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/catalog", catalogHandler)
	http.HandleFunc("/cart", cartHandler)
	http.HandleFunc("/cart/add", addToCartHandler)
	http.HandleFunc("/cart/remove", removeFromCartHandler)
	http.HandleFunc("/checkout", checkoutHandler)
	http.HandleFunc("/admin", adminPanelHandler)
	http.HandleFunc("/admin/users", adminUsersHandler)
	http.HandleFunc("/admin/orders", adminOrdersHandler)
	http.HandleFunc("/admin/update-order-status", adminUpdateOrderStatusHandler)
	http.HandleFunc("/admin/update-user-password", adminUpdateUserPasswordHandler)
	http.HandleFunc("/admin/toggle-admin", toggleAdminHandler)
	http.HandleFunc("/admin/update_order_status", updateOrderStatusHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Запуск сервера
	address := "172.17.4.150:8080"
	log.Printf("Server starting on %s...\n", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
