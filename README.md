# Yisshd

[![Release](https://img.shields.io/github/v/release/jacoblai/yisshd)](https://github.com/jacoblai/yisshd/releases)
[![License](https://img.shields.io/github/license/jacoblai/yisshd)](https://github.com/jacoblai/yisshd/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/jacoblai/yisshd)](https://goreportcard.com/report/github.com/jacoblai/yisshd)
[![OpenIssue](https://img.shields.io/github/issues/jacoblai/yisshd)](https://github.com/jacoblai/yisshd/issues)
[![ClosedIssue](https://img.shields.io/github/issues-closed/jacoblai/yisshd)](https://github.com/jacoblai/yisshd/issues?q=is%3Aissue+is%3Aclosed)
![Stars](https://img.shields.io/github/stars/jacoblai/yisshd)
![Forks](https://img.shields.io/github/forks/jacoblai/yisshd)

## 简介

Yisshd 是 Golang 开发的无依赖 ssh 服务器。

## 特性

* **已经支持**
    - `DenyLogin` 密码错误自动禁止登陆，防止爆力破解
    - `DirectTcpip` 代理模式，方便数据库工具通过ssh跳板内网网络连接数据库
    - `SystemAccount` 支持系统账号验证用户身份
    - `SFTP` 集成SFTP协议
    - 支持 Linux，macOS（操作系统）

* **不被支持**
    - Windows（操作系统）

## 运行

* **参数**
    - `-l` 指定ssh服务端口号

```
//下载执行文件
$ curl https://github.com/jacoblai/yisshd/releases/download/v1.0.0/yisshd_amd64_linux

//升级可执行权限
$ sudo chmod -x yisshd_amd64_linux

// 在22端口启动服务
$ ./yisshd_amd64_linux -l 22
```
