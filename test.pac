var proxy = "SOCKS5 127.0.0.1:2080";

// 不走代理通道的网站
var domains = {
  "127.0.0.1": 1,
  "localhost": 1
};

var direct = 'DIRECT;';

var hasOwnProperty = Object.hasOwnProperty;

function FindProxyForURL(url, host) {
    var suffix;
    var pos = host.lastIndexOf('.');
    pos = host.lastIndexOf('.', pos - 1);
    while(1) {
        if (pos <= 0) {
            if (hasOwnProperty.call(domains, host)) {
                return direct;
            } else {
                return proxy;
            }
        }
        suffix = host.substring(pos + 1);
        if (hasOwnProperty.call(domains, suffix)) {
            return direct;
        }
        pos = host.lastIndexOf('.', pos - 1);
    }
}

