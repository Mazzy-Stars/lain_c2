### lain

Starting today, this framework is open source and can be used by anyone or organization. Currently, it supports platforms such as Windows linux、macos、Android。 The currently supported communication protocols are https \ http

### update

Segmented file transfer

Custom error response

web-ui

sharing host to players

Custom CSS file

### Features

Multiplayer-mode

Dynamic-encryption

Cross-platform

intranet-information-collection

File-operation

web-ui

### Getting Started

```json
{
    "users": [
        {
            "username": "username",
            "password": "dfb95aac49185dd47f008435"
        }
    ]
}
```

Change the password field to md5 encryption and remove the last 8 digits

```cmd
Usage of C:\Users\ADMINI~1\AppData\Local\Temp\go-build2586051263\b001\exe\lain_server.exe:
  -DefaultCert
        Use default public and private keys
  -cert string
        Customize public key path
  -conn
        Use keep alive connection, if this parameter is not present by default, it will be short connection
  -css string
        Use default css file
  -key string
        Customize private key path
  -p string
        Select Port (default "80")
  -protocol string
        Select Protocol(http、https) (default "http")
  -resp-error string
        web error resp (default "error")
```

Use it

```cmd
go run .\lain_server.go -p 80 -conn -resp-error "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.18.0</center></body></html>"
```