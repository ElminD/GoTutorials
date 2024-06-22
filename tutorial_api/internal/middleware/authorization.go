package middleware

import (
	"errors"
	"net/http"

	"api/internal/tools"

	"github.com/avukadin/goapi/api"
	log "github.com/sirupsen/logrus"
)

var UnAuthroizedError = errors.New("Invalid username or token.")

func Authorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		
		var username string = r.URL.Query().Get("username")
		var token = r.Header.Get("Authorization")
		var err error

		if username == "" || token == "" {
			log.Error(UnAuthroizedError)
			api.RequestErrorHandler(w, UnAuthroizedError)
			return
		}

		var database *tools.DatabaseInterface
		database, err = tools.NewDatabase()
		if err != nil {
			api.InternalErrorHandler(w)
			return
		}

		var loginDetails *tools.LoginDetails
		loginDetails = (*database).GetUserLoginDetails(username)

		if(loginDetails == nil || (token != (*loginDetails).AuthToken)) {
			log.Error(UnAuthroizedError)
			api.RequestErrorHandler(w, UnAuthroizedError)
			return
		}

		next.ServeHTTP(w, r)
	})
}