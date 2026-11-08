# RedFilter

App de escritorio para Windows (Avalonia, .NET 10, tema oscuro) con tres funciones en una sola ventana:

- **Modo Dota 2:** reservar la línea para este PC, limitar a los demás dispositivos y dar prioridad al juego.
- **Este PC:** dar prioridad a un programa de este ordenador y limitar la subida de los demás.
- **Mi Wi-Fi:** ver qué dispositivos están usando más la red de tu router y bloquearlos.

Solo habla con este PC y con tu router. No escanea la red, no adivina contraseñas y no envía tramas Wi-Fi.

## Descargar

Cada push a `main` compila la app en GitHub Actions (`.github/workflows/build.yml`):

- **Última compilación:** pestaña *Actions* > ejecución más reciente de *Build* > artefacto `RedFilter-win-x64`. Trae `RedFilter-<versión>-win-x64.exe`, un solo archivo que no necesita tener .NET instalado.
- **Versiones:** al subir una etiqueta `v1.2.3`, el mismo ejecutable se publica en *Releases*.

  ```bat
  git tag v1.1.0
  git push origin v1.1.0
  ```

El ejecutable no está firmado, así que Windows SmartScreen puede avisar la primera vez: *Más información* > *Ejecutar de todas formas*.

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

**Quién usa más.** El router no da bytes por dispositivo; da paquetes enviados y recibidos por cada cliente Wi-Fi (*Active Wireless Client Table*). La app lee esa tabla cada 5 segundos y ordena por paquetes por segundo, así que lo de arriba es lo que más está usando la red *ahora*. La lista lo muestra como uso alto, medio o bajo comparado con el que más usa; el número exacto aparece al pasar el ratón. Los nombres e IP salen de la tabla DHCP. Lo que se conecta a través de un repetidor (por ejemplo un RE1500X) el router lo ve como un solo dispositivo: el repetidor.

**Bloquear.** Usa la *Access Control List* del Wi-Fi del router en modo "Deny Listed": añade la MAC, enciende el bloqueo y vuelve a leer la página para confirmar. "Desbloquear" la quita de la lista; si la lista queda vacía, el bloqueo se apaga. Salvaguardas:

- No deja bloquear este PC, y si este PC está en la lista lo saca antes de encender el bloqueo.
- Avisa antes de bloquear un repetidor, porque deja sin Wi-Fi a todo lo que cuelga de él.
- Si la lista ya tenía otras MAC guardadas con el bloqueo apagado, te las enseña y eliges: bloquearlas también o quitarlas y bloquear solo al dispositivo elegido.
- No toca el modo "Allow Listed", que dejaría fuera a todos los demás.

**Limitar.** Pone un tope de velocidad a un dispositivo sin echarlo: 256 kbps, 512 kbps, 1 Mbps o 2 Mbps de bajada, y un cuarto de eso de subida. Usa *Advanced > IP QoS > Traffic Shaping* (`ipqostc.htm`), que limita por IP:

- Primero fija la IP actual del dispositivo en *DHCP Static IP* (`dhcpip.htm`), para que el límite no se pierda si el router le da otra. Si el dispositivo ya tenía una IP fija distinta, pide reconectarlo antes.
- Si la línea está en "sin límite" (0), le pone el 90% de la velocidad de sincronización ADSL que muestra la página de estado, para que el router sepa cuánto hay que repartir.
- Crea una regla que solo mira la IP de origen. Si ya había una para esa IP, la sustituye. Después vuelve a leer la página para confirmar.
- "Quitar límite" borra la regla. Si no queda ninguna, la línea vuelve a "sin límite". La IP fija se queda, porque no molesta.
- No toca las reglas que tú hayas creado con más condiciones (protocolo, puertos, IP de destino o rangos).

El límite va por IP. A un dispositivo conectado a través de un repetidor no se le puede limitar desde la lista, porque el router solo ve al repetidor, y limitar al repetidor probablemente solo lo frena a él.

El bloqueo es por MAC y solo para el Wi-Fi: no afecta a lo conectado por cable, y un móvil con "dirección MAC privada" puede volver a entrar si cambia de MAC.

**Con VPN.** Si una VPN como WireGuard manda todo por el túnel, el PC no llega a `192.168.1.1`. En WireGuard, quita *Block untunneled traffic (kill-switch)* o excluye `192.168.1.0/24` de *AllowedIPs*.

## Modo Dota 2

El panel de arriba tiene un botón **Activar** que prepara la red para jugar:

- **En el router:** este PC tiene garantizado lo que los demás no pueden usar (con tu línea, unos 1,6 Mbps de bajada y 650 kbps de subida) y puede usar la línea entera cuando está libre. Cada uno de los demás dispositivos de la tabla DHCP recibe su propia regla, y entre todos no pasan de **2,5 Mbps de bajada y 384 kbps de subida**. A ningún dispositivo se le deja con menos de 128/32 kbps. Si ya tenías a alguien limitado más bajo, se respeta tu límite. Los dispositivos que se conectan durante la partida reciben su regla en menos de un minuto.
- **En este PC:** Dota 2 (`dota2.exe`) tiene prioridad y la subida de los demás programas se limita a 256 kbps. Si RedFilter no está abierto como administrador, Windows pide permiso y la app se reinicia.
- **Automático:** si la casilla está marcada, la app ofrece el modo cuando detecta Dota 2 y lo apaga solo 20 segundos después de que lo cierres.
- **Deshacer:** antes de tocar el router, la app guarda en `settings.json` los totales y los límites que había. Al apagar el modo los vuelve a poner, aunque la app se haya cerrado entre medias.

Cada regla cubre una sola IP y ninguna se solapa con otra, así que el resultado no depende de cómo ordene el router sus reglas. Mientras el modo está activo, los botones "Limitar" de la lista se esconden: esas reglas las gestiona el modo.

Dota 2 usa muy poco ancho de banda (menos de 100 kbps). Lo que sube el ping es que otro dispositivo llene la subida, que en ADSL es pequeña. Por eso el modo frena sobre todo la subida de los demás.

## Este PC

La lista muestra los programas que usan la red, uno por programa y el que más usa arriba. **Priorizar** usa directivas QoS de Windows:

- Marca el tráfico de ese programa con DSCP 46.
- Limita la **subida** de los demás programas normales a 256 Kbps, 1 Mbps o 5 Mbps. Las descargas no se limitan.
- No limita los procesos de Windows (svchost y similares). Windows Update y la Optimización de distribución van dentro de svchost; para frenarlas usa *Configuración > Windows Update > Opciones avanzadas > Optimización de distribución*.

Solo se limitan los programas que usan la red, y siguen limitados hasta que pulses **Quitar prioridad**. Mientras RedFilter está abierto, los programas que empiecen a usar la red también se limitan solos; con RedFilter cerrado, no. Las directivas siguen activas aunque cierres la app y Windows las borra al reiniciar. Cambiar la prioridad pide permiso de administrador y reinicia RedFilter elevado.

**Con VPN.** Todo sale cifrado por el túnel: la marca DSCP no llega al router y el límite puede no aplicarse al adaptador de la VPN. La app lo avisa.

El PowerShell elevado ejecuta siempre el mismo script fijo (`-EncodedCommand`). Las rutas, nombres y límites entran como JSON solo ASCII por la entrada estándar y nunca se interpretan como código; nada se escribe en `%TEMP%`.

## Otros routers

El núcleo (`RedFilter.Core`) también tiene clientes para OpenWrt (ubus), ASUSWRT y FRITZ!Box (TR-064), con pruebas, aunque la ventana actual solo usa el del TD-W8961N.
