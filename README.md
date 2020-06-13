# cropass
`cropass` is simple password manager written in [Go](https://golang.org/). `cropass` works anywhere Go runs.
## Install
If you haven't install Go in your computer, please check [https://golang.org/doc/install](https://golang.org/doc/install). Then, you can install cropass with the following command.
```sh
go get github.com/akawashiro/cropass
```
## How to use
First, you should set `CROPASS_PASS_DIR` environment variable. If you don't set, `cropass` uses `cropass-encrypted-passwords` direcotry in the home directory. `cropass` stores encrypted your passwords under the directory.

#### Check your password
```
cropass show {sitename}
```
If you omit {sitename}, it shows all passwords. {sitename} must not be exact. `cropass` shows all password record coordinates.
#### Add new password
```
cropass add {site} {username}
```
#### Add new password (the new password is automatically generated)
```
cropass new {site} {username}
```
#### Import passwords from file
```
cropass import
```
The format of file is following. Although {unixtime} can be arbitrary positive integer, we recommend you to use the current unix time in seconds.
```
{site1} {username1} {password1} {unixtime1}
{site2} {username2} {password2} {unixtime2}
{site3} {username3} {password3} {unixtime3}
...
```
