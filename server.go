package main

import (
	"net/http"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"time"
)

var (
	// Global sql.DB to access the database by all handlers
	db *sql.DB
	err error
	accessToPage bool
	currentUser string
	updateRecord bool
	id string
)

type NewTask struct {
	Id   int
	Task string
	Date string
}

func loginPage(res http.ResponseWriter, req *http.Request) {
	// If method is GET show login.html
	if req.Method != "POST" {
		http.ServeFile(res, req, "login.html")
		return
	}

	// Grab the username/password from the submitted post form
	currentUser = req.FormValue("username")
	password := req.FormValue("password")

	// Grab from the database
	var databaseUsername  string
	var databasePassword  string

	// Search the database for the username provided
	// If it exists grab the password for validation
	err := db.QueryRow("SELECT username, password FROM users WHERE username=?", currentUser).Scan(&databaseUsername, &databasePassword)
	// If not then redirect show error page
	if err != nil {
		showErrorPage(res, "Wrong username")
		//http.Redirect(res, req, "/login", 301)
		return
	}

	// Validate the password
	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	// If wrong password redirect to the login
	if err != nil {
		showErrorPage(res, "Wrong password")
		//http.Redirect(res, req, "/login", 301)
		return
	}

	// If the login succeeded
	accessToPage = true
	http.Redirect(res, req, "/index", 301)
}

func signupPage(res http.ResponseWriter, req *http.Request) {
	// If method is GET show signup.html
	if req.Method != "POST" {
		http.ServeFile(res, req, "signup.html")
		return
	}

	// Grab the username/password from the submitted post form
	username := req.FormValue("username")
	password := req.FormValue("password")

	var user string

	// Search the database for the username provided
	err := db.QueryRow("SELECT username FROM users WHERE username=?", username).Scan(&user)
	checkUser(res, req, password, username, err)
}

func checkUser(res http.ResponseWriter, req *http.Request, password string, username string, err error) {
	switch {
		// Username is available
	case err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			showErrorPage(res, "Unable to create your account")
			//http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		_, err = db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", username, hashedPassword)
		if err != nil {
			showErrorPage(res, "Unable to create your account")
			return
		}

		accessToPage = true
		http.Redirect(res, req, "/index", 301)
		return
		// Some error appeared
	case err != nil:
		showErrorPage(res, "Unable to create your account")
		return
		// Username is already used by someone
	default:
		showErrorPage(res, "This username is already used")
	}
}

func showErrorPage(res http.ResponseWriter, message string) {
	tpl, _ := template.ParseFiles("errorPage.html")
	res.Header().Set("content-type", "text/html; charset=utf-8")
	tpl.ExecuteTemplate(res, "errorPage.html", message)
}

func indexPage(res http.ResponseWriter, req *http.Request) {
	// If method is GET show index.html
	if req.Method != "POST" {
		// If user is not authorized redirect him to login page
		if accessToPage == false {
			http.Redirect(res, req, "/login", 301)
			return
		}

		showTasks(res)
		return
	}
}

func showTasks(res http.ResponseWriter) {
	id := 0
	task := ""
	time := ""
	var listOfTasks []NewTask

	tpl, err := template.ParseFiles("index.html")
	if err != nil {
		showErrorPage(res, "Page not found")
	}
	res.Header().Set("content-type", "text/html; charset=utf-8")

	// Select all tasks from database
	rows, _ := db.Query("select id, task, time from tasks where username = ?", currentUser)

	for rows.Next() {
		err := rows.Scan(&id, &task, &time)
		if err != nil {
			log.Fatal(err)
		}

		listOfTasks = append(listOfTasks, NewTask{
			Id: id,
			Task: task,
			Date: time,
		})
	}

	tpl.Execute(res, listOfTasks)
	defer rows.Close()
}

func editPage(res http.ResponseWriter, req *http.Request) {
	// If method is GET show edit.html
	if req.Method != "POST" {
		// If user is not authorized redirect him to login page
		if accessToPage == false {
			http.Redirect(res, req, "/login", 301)
			return
		}

		tpl, _ := template.ParseFiles("edit.html")
		res.Header().Set("content-type", "text/html; charset=utf-8")
		tpl.Execute(res, "")
		return
	}

	// Grab the task/date from the submitted post form
	task := req.FormValue("task")
	date := req.FormValue("date")
	// Parse the date
	time, err := time.Parse("2006-01-02", date)
	if err != nil {
		showErrorPage(res, "Wrong date format")
		return
	}

	editTask(res, task, time)
	http.Redirect(res, req, "/index", 301)
}

func editTask(res http.ResponseWriter, task string, time time.Time) {
	if updateRecord == true {
		// Update record in database
		_, err = db.Exec("UPDATE tasks SET task = ?, time = ? WHERE id = ?", task, time, id)
		if err != nil {
			showErrorPage(res, "Unable to update your task")
			return
		}

		updateRecord = false
	} else {
		// Insert new record in database
		_, err = db.Exec("INSERT INTO tasks(username, task, time) VALUES(?, ?, ?)", currentUser, task, time)
		if err != nil {
			showErrorPage(res, "Unable to create your task")
			return
		}
	}
}

func updateTask(res http.ResponseWriter, req *http.Request) {
	tpl, err := template.ParseFiles("edit.html")
	if err != nil {
		showErrorPage(res, "Page not found")
	}

	res.Header().Set("content-type", "text/html; charset=utf-8")

	// Grab task's id from the submitted post form
	id = req.FormValue("update")
	task := ""

	// Search for the task by id
	rows, err := db.Query("select task from tasks where id = ?", id)
	if err != nil {
		showErrorPage(res, "Unable to load your task")
		return
	}

	if rows.Next() {
		err := rows.Scan(&task)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Show the edit page with task which needs to be edited
	updateRecord = true
	tpl.Execute(res, task)
	defer rows.Close()
}

func deleteTask(res http.ResponseWriter, req *http.Request) {
	// Grab task's id from the submitted post form
	id = req.FormValue("delete")

	// Delete record from database
	_, err := db.Query("DELETE FROM tasks WHERE id = ?", id)
	if err != nil {
		showErrorPage(res, "Unable to delete your task")
		return
	}

	http.Redirect(res, req, "/index", 301)
}

func main() {
	// Create an sql.DB and check for errors
	db, err = sql.Open("mysql", "root:password@/todolist")
	if err != nil {
		panic(err.Error())
	}

	defer db.Close()
	// Test the connection to the database
	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	// Handler to handle serving static files (.css or .png) from a specified directory
	http.Handle("/bin/", http.StripPrefix("/bin/", http.FileServer(http.Dir("bin"))))

	http.HandleFunc("/signup", signupPage)
	http.HandleFunc("/login", loginPage)
	http.HandleFunc("/", loginPage)
	http.HandleFunc("/index", indexPage)
	http.HandleFunc("/edit", editPage)
	http.HandleFunc("/update", updateTask)
	http.HandleFunc("/delete", deleteTask)
	http.ListenAndServe(":8080", nil)
}
