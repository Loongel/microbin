## bugs 记录 2025-07-30
1. [ ] 资源查看页面，复制重定向url,没有优先获取自定义路径，而是hash_id或动物字符串
2. [ ] 资源查看页面，qr的url,没有优先获取自定义路径，而是hash_id或动物字符串
3. [ ] list页面 复制重定向路径时，只有路径后缀，没有http(s)://主机名等前面部分
4. [x] 设置了 MICROBIN_ETERNAL_PASTA=true,但是 MICROBIN_PUBLIC_PATH 没有设置或者设置为空，资源创建页面，仍然没有never过期的选项
5. [x] 设置了 MICROBIN_UPLOADER_PASSWORD="password" ，资源创建页面，仍然可以不用密码就上传文件
