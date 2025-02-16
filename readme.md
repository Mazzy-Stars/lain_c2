### lain

Starting today, this framework is open source and can be used by anyone or organization. Currently, it supports platforms such as Windows linux、macos、Android。 The currently supported communication protocols are https \ http

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
go to http://localhost/login
Change the password field to md5 encryption and remove the last 8 digits

go run .\lain_server.go -h

-DefaultCert
        Use default public and private keys
  -N int
        Discard the handshake packet (default is 90) (default 90)
  -cert string
        Customize public key path
  -conn
        Use keep alive connection, if this parameter is not present by default, it will be short connection
  -key string
        Customize private key path
  -p string
        Select Port (default "80")
  -protocol string
        Select Protocol(http、https) (default "http")

I usually

```cmd
go run .\lain_server.go -p 6643 -conn
```
