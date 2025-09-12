![start.png](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/start.png)

## lain command-control-frame work

golang framework,agent it supports platforms such as Windows linux、macos、Android。 The currently supported communication protocols are https \ http

### Features

Custom server error response

sharing host to players

Custom CSS file

Multiplayer-mode

Dynamic-encryption

Cross-platform

intranet-information-collection

File Browser

Segmented file transfer

web-ui

Customize Plugins code

group jobs

jobs、result cache

msg queue operation

Customize implants request parameters

Client history file directory cache

Access control whitelist

Customize log language messages

### Getting Started

```json
{
    "users": [
        {
            "username": "aaf95bdd47f00d8435c49185",
            "password": "dfb95aac49185dd47f008435"
            //Change the password and username field to md5 encryption and remove the last 8 digits
        }
    ]
}
```

```cmd
Usage of C:\Users\ADMINI~1\AppData\Local\Temp\go-build3450987718\b001\exe\server.exe:
  -DefaultCert
        Use default public and private keys
  -cert string
        Customize public key path
  -css string
        Use default css file
  -http
        Use HTTP instead of HTTPS
  -key string
        Customize private key path
  -p string
        Port (default "443")
  -resp-error string
        web error resp (default "error")
  -title string
        web ui title (default "connect")
```

![image-20250722224250819](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/help.png)

### Start server

Open the listening c2 service port. In order to better conceal and simulate real traffic, all traffic is get and post forms, write the request parameters for communication with the implant, and the parameters must not be repeated. Then select http\https

![lain_c2/html/image-1.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-1.png)

After the update, a custom Base64 encoding feature has been added. It supports generating either a random encoding table or a user-provided table that conforms to the Base64 rules. Each listening service is associated with a unique encoding table.

![lain_c2/html/image-2.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-2.png)

Click the corresponding platform link to generate the implant code

![lain_c2/html/image-3.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-3.png)

### Plugin Code into Implants

Each listening service inserts the same plug-in code

![lain_c2/html/image-6.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-6.png)

plugin code be like this,the top is the plugin code, then you must select the number of parameters (not less than the actual parameters), compress the Go language code into one line and enter the necessary parameters into the input box. The last input box is the description of the parameters

![lain_c2/html/image-4.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-4.png)

 the description of the parameters: msg1, msg2; description of msg1 parameters, description of msg2 parameters (the corresponding parameter descriptions are separated by check marks and corresponding indexes)

![lain_c2/html/image-9.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-9.png)

Plugin code for different platforms

![lain_c2/html/image-8.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-8.png)

### change Implant info

Modify the input directly and press the Save Change button

![lain_c2/html/image-7.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-7.png)

### Implant Terminal

![lain_c2/html/image-10.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-10.png)

### File Browser

![lain_c2/html/image-11.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-11.png)

### sniff host choose port

![lain_c2/html/image-12.png at main · Mazzy-Stars/lain_c2](https://github.com/Mazzy-Stars/lain_c2/raw/main/html/image-12.png)

    scan host [target 192.168.1(1,20,45...)or(1-253)]	[range(1,20,45...)or(1-65534)]	[delay])
    scan port [target 192.168.1.1] [range(1,20,45...)or(1-65534)]	[delay])
