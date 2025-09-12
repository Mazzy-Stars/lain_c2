//plugin-html
package web_ui
import (
    "fmt"
    "net/http"
)
func PluginHtml(error_str string, sessionSlice []string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        //必须先登录
        _, ok := CheckUserSession(r, sessionSlice, error_str)
        if !ok {
            fmt.Fprint(w, error_str)
            return
        }
        if r.Method == http.MethodGet {
            html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="stylesheet" href="/lain.css">
</head>
<body>
    <script>
    window.addEventListener('DOMContentLoaded', () => {
        let urlParams = new URLSearchParams(window.location.search);
        let uid = urlParams.get('uid');
        let os = urlParams.get('os');
        let paramDescList = urlParams.get('paramDescList');
        let codeword = urlParams.get('codeword');
        let paramDescArray = paramDescList ? decodeURIComponent(paramDescList).split(',') : [];

        if (!uid || !os || !paramDescList || !codeword) {
            alert("Missing required parameters in the URL.");
            return;
        }

        let dialog = document.createElement('form'); 
        dialog.style.border = "1px solid #ccc";
        dialog.style.padding = "16px";
        dialog.style.width = "95%";
        dialog.style.margin = "40px auto";
        dialog.style.backgroundColor = "#f9f9f9";
        dialog.style.borderRadius = "8px";
        dialog.style.boxShadow = "0 2px 8px rgba(0,0,0,0.2)";

        paramDescArray.forEach(desc => {
            let input = document.createElement('input');
            input.type = 'text';
            input.placeholder = desc;
            input.style.display = "block";
            input.style.margin = "8px 0";
            input.style.width = "90%";
            input.style.padding = "8px";
            input.style.boxSizing = "border-box";
            dialog.appendChild(input);
        });

        let submitButton = document.createElement('button');
        submitButton.textContent = 'send';
        submitButton.style.padding = "10px 20px";
        submitButton.style.marginTop = "12px";
        submitButton.style.cursor = "pointer";

        submitButton.onclick = function(event) {
            event.preventDefault();  // 阻止默认提交行为，防止页面刷新
            sendMsg();
        };

        dialog.appendChild(submitButton);

        document.body.appendChild(dialog);

        function sendMsg() {
            let inputs = dialog.querySelectorAll('input[type="text"]');
            let msgParts = [];
            for (let input of inputs) {
                let value = input.value.trim();
                if (!value) {
                    alert("Please fill in all fields.");
                    return;
                }
                msgParts.push(value);
            }

            let msg = codeword + '^' + msgParts.join('^');

            fetch('/user_index?op=msg&uid=' + encodeURIComponent(uid) + '&msg=' + encodeURIComponent(msg)+'&Taskid=pluginTask', {
                method: 'GET'
            })
            .then(response => {
                if (response.ok) {
                    alert("Message sent successfully!");
                    inputs.forEach(input => input.value = '');
                } else {
                    return response.text().then(text => {
                        throw new Error(text);
                    });
                }
            })
            .catch(error => {
                console.error("Failed to send message:", error);
                alert("Failed to send message: " + error.message);
            });
        }
    });
</script>
</body>
</html>
`
            w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
			return
		}
	}
}