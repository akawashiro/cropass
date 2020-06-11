# cropass
cropass is simple password manager written in Go.
## Install
```sh
go get https://github.com/akawashiro/cropass
```
## How to use
First, you must set `CROPASS_PASS_DIR` environment variable. cropass stores encrypted your passwords under the directory.

#### Check your password
```
cropass show {sitename}
```
#### Add new password
```
cropass add {site} {username} {password}
```
#### Add new password (password is automatically generated)
```
cropass new {site} {username}
```
#### Import passwords from file
```
cropass import
```