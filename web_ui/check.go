package web_ui
import (
	"net/http"
	"strings"
)
func CheckUserSession(r *http.Request, sessionSlice []string, error_str string) (string, bool) {
    usernameCookie, err := r.Cookie("cookie")
    if err != nil {
        return error_str, false
    }
    var currentUsername string
    foundUser := false
    for _, session := range sessionSlice {
        if session == usernameCookie.Value {
            foundUser = true
            parts := strings.Split(session, "=")
            if len(parts) == 2 {
                currentUsername = parts[1]
            }
            break
        }
    }
    if !foundUser {
        return error_str, false
    }
    return currentUsername, true
}

func WriteCustomError(w http.ResponseWriter, status int, body string, extra map[string]string) {
	for k, v := range extra {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
