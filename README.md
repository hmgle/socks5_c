# socks5_c

[![Build Status](https://travis-ci.org/hmgle/socks5_c.png?branch=master)](https://travis-ci.org/hmgle/socks5_c)

一个轻量级的 [socks5](http://www.ietf.org/rfc/rfc1928.txt) 代理, 采用单进程多路复用 IO 模式. 可用于科学上网.

**目前仅支持 UNIX/Linux 平台**

## 使用方法

### 编译:

```bash
$ make
```

生成的目标文件有:

* **local**: 运行在本地, 是沟通浏览器等应用程序与 **server** 的桥梁, 处理使用 [socks5](http://www.ietf.org/rfc/rfc1928.txt) 代理的应用程序的请求, 转发给 **server**
* **server**: 响应 **local** 的请求, 获取网站数据处理后返回给 **local**

### 翻墙实例:

假设墙外的服务器地址为: `104.167.51.31`, 在服务器上运行 **server**:

```bash
$ # 在 1984 端口监听等待连接, 使用 "test" 字符串加解密
$ ./server -p 1984 -e "test"
```

在本地运行 **local**:

```bash
$ # 连接服务器的 1984 端口, 在本地 2080 端口监听, 使用 "test" 字符串加解密
$ ./local -l 104.167.51.31 -p 1984 -s 2080 -e "test"
```

浏览器设置:
socks 主机填写 127.0.0.1, 端口填写: `2080`, 选择 `SOCKS v5` 代理.

推荐 Firefox 的 `FoxyProxy` 插件. 当然不使用插件也可以使用 SOCKS v5 代理.

## 授权协议

socks5_c 在 MIT license 协议下发布. 参见 [LICENSE.md](LICENSE.md) 文件.
