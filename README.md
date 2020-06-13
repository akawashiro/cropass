# cropass
cropass is simple password manager written in Go. cropass works anywhere golang runs.
## Install
```sh
go get github.com/akawashiro/cropass
```
## How to use
First, you should set `CROPASS_PASS_DIR` environment variable. If you don't set, `cropass` uses `cropass-encrypted-passwords` direcotry in the home directory. `cropass` stores encrypted your passwords under the directory.

#### Check your password
```
cropass show {sitename}
```
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