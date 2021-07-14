# RDP弱密码检测

项目为检测RDP/SYS密码，并通过模拟登录RDP过滤无效账户。

## 检测对象

Windows系统登录密码，侧重Winserver系统。模拟登录功能适用win8/winserver2012及以上系统，低版本系统OpenSSL库不兼容。

## 检测流程

1. 备份系统登录信息相关注册表，及sam及system项；
2. 解析相关项得到登录账户及对应NTLM哈希；
3. 通过弱密码表生成对应哈希进行爆破；
4. 查询当前系统RDP端口及开启状态；
5. 使用破解出的账户模拟登录RDP过滤无效账户；
6. 验证成功的即添加到最终结果。

# RDP-Password-checker