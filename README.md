# RedFilter

RedFilter is a Windows desktop app for your own PC and your own home router.

It can give one program priority on the laptop by using Windows QoS policies, and it can sign in to a router you configure and list the clients that router reports. It does not scan the network, guess passwords, or send Wi-Fi frames from the PC.

## What you need

- Windows 10 or Windows 11, 64-bit
- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- An administrator account. The app manifest asks Windows for elevation because QoS policy changes require it.

## Build and run

From this folder:

```bat
dotnet build -c Release
dotnet run --project src\RedFilter.App -c Release
```

Or start the built program:

```bat
src\RedFilter.App\bin\Release\net10.0-windows\RedFilter.exe
```

Windows shows a User Account Control prompt. Accept it. If you start the app without elevation, the Network page explains that QoS changes are blocked until you run it as administrator.

The app window has two pages: **Network** and **Router**.

## Network page

The list shows each running process with its name, PID, program path, TCP connection count, UDP endpoint count, and the current TCP download and upload rate when Windows connection statistics provide them.

Choose a process and **Give the network to the selected program**. RedFilter then:

- Marks that program path with DSCP 46 (expedited forwarding) through `New-NetQosPolicy`
- Limits outbound traffic from other ordinary programs to the rate you pick (256 Kbps, 1 Mbps, or 5 Mbps)
- Leaves Windows system processes unthrottled so the PC keeps working

**Turn filter off** removes every QoS policy whose name starts with `RedFilter-` and restores normal sharing.

The page shows the program that currently owns the network. Windows matches the program path, so every process running that same program is included. The limit applies to outbound traffic. It does not cap downloads. Policies are stored in the active QoS store: they remain after you close RedFilter, and Windows drops them on reboot.

## Router page

Enter the address of your own router, the admin username, and the password. The password is encrypted with Windows DPAPI for the current user and stored under `%LOCALAPPDATA%\RedFilter`. It is not written into `settings.json`. RedFilter sends it only to the host you entered.

Before a router answers, the page is still usable: you can edit the address, username, brand, and model, fill the address from this PC's default gateway, and save. The client list stays empty. The status line says exactly which of the address, username, or password is still missing. RedFilter does not guess a password and does not probe other hosts.

**Test connection** identifies the admin API and, when it recognizes one, signs in:

| Router | What works |
| --- | --- |
| OpenWrt (ubus) | Lists Wi-Fi clients (MAC, name when `luci-rpc` knows it, byte counters). Disconnect, block for 30 minutes, and unblock each send one `hostapd` admin request for that client. |
| ASUSWRT | Lists online clients from `appGet.cgi`. Disconnect and block are not sent, because the stock API has no confirmed single-client Wi-Fi disconnect and restarting wireless would drop every device. |
| FRITZ!Box (TR-064) | Lists hosts, sets realtime priority, and sends Wake-on-LAN. Link speed is the router's Mbit/s figure, not a live byte counter. TR-064 has no documented per-client Wi-Fi disconnect, so that action is not sent. |

If the model is unknown, login fails, or a call is missing, the status line reports that and the form stays editable. A block or disconnect is one admin request per click for one unicast MAC. RedFilter does not inject packets and does not repeat the request.

## Tests

```bat
dotnet test -c Release
```
