DNSSVC.R4X
==========

DNSSVC.R4X ist der DNS-Resolver-Service.

Projektstruktur seit 0.51.19:
- `build.zig` baut den Service als eigenes SDK-Projekt.
- `build.zig.zon` bindet `r4os_sdk` als Paket.
- `module.R4MF` beschreibt Artefakt, Zielpfad, Imports, Startdaten und Contract.

Build:

    cd Code\System\Services\DnsService
    ..\..\..\DevTools\Zig\zig.exe build

Ergebnis:

    Code\System\Services\DnsService\zig-out\DNSSVC.R4X

Contract:
- R4XStart-Entry: `dnssvc_main`
- App-Klasse: `service`
- R4L-Imports: `R4SYS`, `R4NET`
- Service-Name: `DNSSVC`
- Standardargumente: `/RUN`
- Zielpfad im Image: `C:\R4OS\SERVICES\DNSSVC.R4X`

