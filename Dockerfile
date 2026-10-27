# Microsoft's .NET SDK image includes PowerShell (pwsh).
# The same diagnose.ps1 script runs on Windows to scan and in Linux to render.
FROM mcr.microsoft.com/dotnet/sdk:8.0
ENV HOME=/tmp \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1
WORKDIR /app
COPY diagnose.ps1 ./diagnose.ps1
USER 65534:65534
ENTRYPOINT ["pwsh", "-NoLogo", "-NoProfile", "-File", "/app/diagnose.ps1", "__render"]
