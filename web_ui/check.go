package web_ui
import (
	"net/http"
)

func CheckUserSession(r *http.Request, sessionSlice []string) bool {
	usernameCookie, err := r.Cookie("cookie")
	if err != nil {
		return false
	}
	for _, session := range sessionSlice {
		if session == usernameCookie.Value {
			return true
		}
	}
	return false
}

func WriteCustomError(w http.ResponseWriter, status int, body string, extra map[string]string) {
	for k, v := range extra {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
