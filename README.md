# DTEdrawMax
A keygen of a certain graphic design software

# 软件整体的加密思路:

软件整体的加密思路大致如下几个步骤:
1. 软件采用C/S结构的网络认证方法。
2. 获取系统的硬件标识符(后面详细说明获取方法)提交给服务端，服务端生成任意20位字符(字母数字组合)作为序列号(用作用户身份标识)。
3. 服务端用RSA的私钥对硬件标识符进行加密得到的密文就是激活码，用户名随意填写。
4. 用户点击激活时，除了校验填写的数据是否合规之外，还会发请求给服务端，服务端校验序列号是否存在，以此判断激活是否成功。
5. 如果网络请求失败可以离线填写激活码来激活(这就留下了安全隐患，可以绕过网络验证)。
6. 每次软件启动，都会将激活码用公钥解密并与系统的硬件标识符进行校验，一致就认证成功，否则就认证失败(这里也存在隐患，要暴力破解可以从这里入手，但是暗桩较多不建议从这里入手)。

# 破解的思路与方法

由于可以本地验证，我们可以生成自己的RSA公钥私钥，来对系统的硬件标识符进行加密，以此来绕过软件的认证。

通过分析可知在软件的`ObjectModule.dll(libObjectModule.dylib)`中存储了RSA加密的公钥，将其替换成我们自己的，然后我们用自己的私钥加密硬件标识符，这样就可以认证成功了。

另外需要说明的一点是，MACOSX系统中`libObjectModule.dylib`存储公钥的空间不足。我对OSX系统的`mach-o文件格式`不了解所以只能通过内存补丁的方法来替换公钥，大致思路是:
1. 通过分析可知`libObjectModule.dylib`文件加载后会在dllmain将公钥赋值给到导出符号: `__ZN12LocalizeUtil10s_locCodesE`中，Mach0View查看导出符号的偏移是: `0x0535be0`.
2. 自己写程序，监控这个导出符号值的变化，来替换公钥, 我是另起了个线程监控这个值。本来是想写钩子实现，但是C代码用FishHook库这种导入表钩子不知道如何挂钩dllmain这种方法，貌似它只能挂钩 nl或者la类的符号表。
3. 这个导出符号的内存结构是QT的`QByteArray`的内存结构，所以我用QT5写这个dylib(`libDTPatcher.1.0.0.dylib`)直接替换不用自己拼这个内存结构了。
4. 用 `yololib` 添加自己的dylib为依赖，我找了一个比较小的dylib: `libImporter.1.0.0.dylib`来加载自己的dylib文件。


# 硬件标识符的获取方法

---

整个硬件信息的获取及编码方法是通过 `libImporter.1.0.0.dylib` 的中导出方法: `__int64 __fastcall PDFExporter::exportEffectShine(PDFExporter *this)` 进行的，有兴趣的童鞋可以跟着一起分析一下，这下只说结果，不贴代码了。

### Windows 环境

1. 通过 `wmic CPU get ProcessorID` 命令获取CPUID。
> 例如得到的是: `BFEBFBFF00040661`
2. 通过 `wmic diskdrive get SerialNumber` 命令获取硬盘序列号。
> 例如得到的是: `4e4d534246484b524e314d443733565243444a57`
3. 通过 `wmic csproduct get UUID` 命令获取主板的UUID。
> 例如得到的是: `EE049876-335D-C447-BD48-A27C393B5C95`
4. 将上面得到的字符串用 `-` 字符以 UUID-硬盘序列号-CPUID 的顺序拼接起来。
> 例如得到的是: `EE049876-335D-C447-BD48-A27C393B5C95-4e4d534246484b524e314d443733565243444a57-BFEBFBFF00040661`

将这些字符串用MD5加密，并截取密文的6~9个字符。如下: 

```
// 1. `EE049876-335D-C447-BD48-A27C393B5C95-4e4d534246484b524e314d443733565243444a57-BFEBFBFF00040661` 用MD5加密并截取字符串: 
664BF64B6C183B297BC26A723EED0E23
     ----
     5(4): 64B6

// 2. 主板UUID `EE049876-335D-C447-BD48-A27C393B5C95` 用MD5加密并截取字符串: 
22D148767E9169B049BF7ADC653DB4D6
     ----
     5(4): 8767


// 3. 硬盘序列号 `4e4d534246484b524e314d443733565243444a57` 用MD5加密并截取字符串: 
4400AAFBA449B4CBF8DADB3F78CC0405
     ----
     5(4): AFBA


// 4. 将上面截取得到的字符转换成小写字母拼接起来得到硬件标识符: `64b68767afba`

```

### MacOSX 环境

1. 获取硬件UUID
```
ioreg -c IOPlatformExpertDevice | grep 'IOPlatformUUID'   // 这样加密后得到第二组token
```
>   ` | "IOPlatformUUID" = "BFE1056A-DBE1-5CC2-BDB8-EBC3A80C108B"`
>  加密得到: `22B76BFDD00D1E58BC2733D2E8FE93C9`，截取6~9个字符得到: `BFDD`

2. 获取系统序列号
```
ioreg -c IOPlatformExpertDevice | grep 'IOPlatformSerialNumber'
```
> `    | "IOPlatformSerialNumber" = "C02NGJPVG3QC"`
> 加密得到: `5AE2186EB36AD059F3A7DDDC4A8D7FD1`，截取6~9个字符得到: `86EB`

3. 将上面两个完整字符串用`-`连接起来，得到:
> `BFE1056A-DBE1-5CC2-BDB8-EBC3A80C108B-C02NGJPVG3QC`
> 加密得到: `D7207A086F1353DABCFBAA52B8A57DC3`，截取6~9个字符得到: `A086`

4. 将上面截取出来的字符串按照3，1，2的顺序排列并转换成小写字母得到硬件标识符: `a086bfdd86eb`


