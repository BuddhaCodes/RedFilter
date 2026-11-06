# RedFilter

App de escritorio para Windows (Avalonia, .NET 10) con dos funciones en una sola ventana:

- **Este PC:** dar prioridad a un programa de este ordenador y limitar la subida de los demás.
- **Mi Wi-Fi:** ver qué dispositivos están usando más la red de tu router y bloquearlos.

Solo habla con este PC y con tu router. No escanea la red, no adivina contraseñas y no envía tramas Wi-Fi.

## Compilar y ejecutar

Necesitas Windows 10/11 de 64 bits y el [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bat
dotnet run --project src\RedFilter.App
```

Tests:

```bat
dotnet test -c Release
```

## Mi Wi-Fi

Compatible con el **TP-Link TD-W8961N v5** (firmware Realtek, panel en `http://192.168.1.1`).

La primera vez solo pide la contraseña del router; la dirección sale de la puerta de enlace de Windows y el usuario es `admin`. Si marcas "Recordarla", se guarda cifrada con DPAPI para tu usuario de Windows en `%LOCALAPPDATA%\RedFilter` y la app se conecta sola al abrirse. El inicio de sesión envía lo mismo que la página del router: `md5(usuario)` y `md5(contraseña)` a `login.cgi`. Si la sesión caduca, la app vuelve a entrar sola una vez.

**Quién usa más.** El router no da bytes por dispositivo; da paquetes enviados y recibidos por cada cliente Wi-Fi (*Active Wireless Client Table*). La app lee esa tabla cada 5 segundos y ordena por paquetes por segundo, así que lo de arriba es lo que más está usando la red *ahora*. Los nombres e IP salen de la tabla DHCP. Lo que se conecta a través de un repetidor (por ejemplo un RE1500X) el router lo ve como un solo dispositivo: el repetidor.

**Bloquear.** Usa la *Access Control List* del Wi-Fi del router en modo "Deny Listed": añade la MAC, enciende el bloqueo y vuelve a leer la página para confirmar. "Desbloquear" la quita de la lista; si la lista queda vacía, el bloqueo se apaga. Salvaguardas:

- No deja bloquear este PC, y si este PC está en la lista lo saca antes de encender el bloqueo.
- Avisa antes de bloquear un repetidor, porque deja sin Wi-Fi a todo lo que cuelga de él.
- Si la lista ya tenía otras MAC guardadas con el bloqueo apagado, te las enseña y eliges: bloquearlas también o quitarlas y bloquear solo al dispositivo elegido.
- No toca el modo "Allow Listed", que dejaría fuera a todos los demás.

**Con VPN.** Si una VPN como WireGuard manda todo por el túnel, el PC no llega a `192.168.1.1`. En WireGuard, quita *Block untunneled traffic (kill-switch)* o excluye `192.168.1.0/24` de *AllowedIPs*.

## Este PC

La lista muestra los programas que usan la red, uno por programa y el que más usa arriba. **Priorizar** usa directivas QoS de Windows:

- Marca el tráfico de ese programa con DSCP 46.
- Limita la **subida** de los demás programas normales a 256 Kbps, 1 Mbps o 5 Mbps. Las descargas no se limitan.
- No limita los procesos de Windows (svchost y similares). Windows Update y la Optimización de distribución van dentro de svchost; para frenarlas usa *Configuración > Windows Update > Opciones avanzadas > Optimización de distribución*.

Solo se limitan los programas que usan la red, y siguen limitados hasta que pulses **Quitar prioridad**. Las directivas siguen activas aunque cierres la app y Windows las borra al reiniciar. Cambiar la prioridad pide permiso de administrador y reinicia RedFilter elevado.

**Con VPN.** Todo sale cifrado por el túnel: la marca DSCP no llega al router y el límite puede no aplicarse al adaptador de la VPN. La app lo avisa.

El PowerShell elevado ejecuta siempre el mismo script fijo (`-EncodedCommand`). Las rutas, nombres y límites entran como JSON solo ASCII por la entrada estándar y nunca se interpretan como código; nada se escribe en `%TEMP%`.

## Otros routers

El núcleo (`RedFilter.Core`) también tiene clientes para OpenWrt (ubus), ASUSWRT y FRITZ!Box (TR-064), con pruebas, aunque la ventana actual solo usa el del TD-W8961N.
