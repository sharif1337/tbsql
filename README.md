# tbsql
`Time-Based SQLi Scanner`
## Installation
```
go install -v github.com/sharif1337/tbsql@latest
```
## Usage
## Single URL
```
tbsql -u "http://testphp.vulnweb.com/listproducts.php?cat=2"
```
## Multiple URLs
```
tbsql -f urls.txt
```
## Custom Paylaod
Set the same time in the payload and `-t` flag
```
tbsql -f urls.txt -p "+ORDER+BY+SLEEP(5)--+-" -t 5
```

[![Facebook](https://img.shields.io/badge/Facebook-Profile-blue?style=flat-square&logo=facebook)](https://www.facebook.com/sharifansari00)
