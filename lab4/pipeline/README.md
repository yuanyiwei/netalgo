# 运行方式
``` bash
    make
    sudo ./build/server-main -c 3f -n 6
```
> lcore mask: 0x111111：使用0号，1号，2号，3号，4号，5号核。

# 注意事项
- 本实例经过实测可以实现10000个包的完全收发，可以在此基础上继续优化。
