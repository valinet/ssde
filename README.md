# Self Signed Driver Enabler for Windows

SSDE is a collection of utilities that help in having Windows load your self signed (custom signed) drivers when Secure Boot is on and you own the platform key of the system, instead of resorting to running the system in test mode.

This is based off great work by the following:

* [Licensed Driver Signing in Windows 10](https://www.geoffchappell.com/notes/windows/license/customkernelsigners.htm) [1]- original very detailed explanation and PoC
* [HyperSine / Windows10-CustomKernelSigners](https://github.com/HyperSine/Windows10-CustomKernelSigners) [2] - original working implementation

I recommend reading the 2 resources above before proceeding, at least familiarizing well with what they describe. This README is not step by step, but it includes my observations on how to get this working on current Windows releases starting from the directions set by those.

## Disclaimer

This is not entirely new code, but merely an adaptation of work already available in the repositories listed above. For this project, what I did was rewrite the kernel driver needed to maintaining the licensing state starting from Geoff's example and using the essential stuff from the original ckspdrv.sys driver.

Also, I also put together a helper app that interrogates this new driver and obtains the number of times the policy has been enforced on the system (`ssde_info`), a helper app that obtains the policy status from the registry in user mode (`ssde_query`) and also included the largely unchanged CustomKernelSigner enabler, with only bug fixes so that it does not boot loop anymore (`ssde_enable` aka `EnableCKS.exe`).

## Precompiled binaries

Go to [Releases](https://github.com/valinet/ssde/releases) to get precompiled files that you can use.

I have personally tested this and it works on Windows 11 build 22000.1.

## How to?

Please follow the tutorial in [2] and apply what I describe in my notes below.

#### 2.3 Build kernel code-sign certificate rules

I recommend using the policy from [1] instead of the one recommended in [2], which is available [here](https://www.geoffchappell.com/notes/windows/license/selfsign.xml.htm) and [here](https://www.geoffchappell.com/notes/windows/license/_download/sipolicy.zip) (already in binary form, so that you do not necessarily require Enterprise or Education editions of Windows).

#### 2.5 Enable CustomKernelSigners

There are 2 ways to do this:

1. Use `ssde_enable.exe` method - this will reboot Windows in setup mode, where the policy can be changed from user mode, and then reboot the system; at next boot, the policy will be licensed and enabled (check `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\CI\Protected\Licensed` and with `ssde_query`)
2. Use the trick mentioned in the end of article [1], specifically the section "Start Another Windows".

Both of these methods will land you on the desktop being able to load any self signed driver. Do not restart, as the policy change is not permanent and will revert to previous status. You have to install the `ssde.sys` driver in the system in order for the status to be preserved on subsequent boots.

The reason the original `EnableCKS.exe` boot looped is because on newer Windows versions, only the policy `CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners` exists anymore. `CodeIntegrity-AllowConfigurablePolicy` is not available anymore and does not seem necessary to add anymore.

#### 2.5 Persist CustomKernelSigners

Here, you have to install the driver. My command for signing it is (do this beforehand getting here, ideally):

```
signtool sign /fd sha256 /a /ac .\localhost-root-ca.der /f .\localhost-km.pfx /p password /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp ssde.sys
```

