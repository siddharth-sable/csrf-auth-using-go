package templates

import (
	"html/template"
	"log"
	"net/http"
)

type LoginPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RegisterPage struct {
	BAlertUser bool
	AlertMsg   string
}

type Restricted struct {
	CsrfSecret    string
	SecretMessage string
}

var templates = template.Must(template.ParseFiles("./server/templates/templateFiles/login.tmpl", "./server/templates/templateFiles/register.tmpl", "./server/templates/templateFiles/restricted.tmpl"))

func RenderTemplate(w http.ResponseWriter, tmpl string, p interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".tmpl", p)
	if err != nil {
		log.Printf("you have template error here %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
