# Diagnose

**Read-only Windows program and service diagnostics, with clear CLI reports rendered in Docker.** Search using a program or service name, review possible issues, and get cautious troubleshooting suggestions. No predefined program list is required.

> **Windows-only scanner.** The host PowerShell script reads Windows data; the Linux Docker container formats the report. Building the Docker image alone does **not** install the Windows `diagnose` command.

## Installation — choose a method

### Method 1: Clone the repository and build locally

Requirements: Windows 10/11, Windows PowerShell 5.1 or PowerShell 7+, Docker Desktop running Linux containers, and Git.

```powershell
git clone https://github.com/ThomasReniers/Diagnose.git
cd Diagnose
docker build --no-cache -t diagnose:latest .
```

To use it from anywhere, add the cloned **Diagnose** folder to your user `PATH` (it contains `diagnose.bat`), then reopen your terminal. Alternatively, copy `diagnose.bat` into an existing `Batchfiles` folder that is already on your `PATH`, **provided that** `Batchfiles` and `Diagnose` are siblings. The launcher supports both layouts.

### Method 2: Build the Docker image directly from GitHub

No clone is needed **for the Docker image**:

```powershell
docker build --no-cache -t diagnose:latest https://github.com/ThomasReniers/Diagnose.git
```

**The CLI still needs the two local Windows files.** Download [diagnose.ps1](https://raw.githubusercontent.com/ThomasReniers/Diagnose/main/diagnose.ps1) and [diagnose.bat](https://raw.githubusercontent.com/ThomasReniers/Diagnose/main/diagnose.bat) to a local folder called `Diagnose`; create `Diagnose\reports` if desired (the script also creates it automatically). Add that folder to your Windows user `PATH` and reopen the terminal. If you already have a `Batchfiles` folder in `PATH`, you may instead put `diagnose.bat` there, with `Diagnose` as its sibling folder.

> Download the **raw** files, not the GitHub HTML preview pages. The launcher and script must be the **same version** as the image.

**PowerShell security:** The launcher does not override execution policies. It runs the script using the policy already configured on your computer. If Windows blocks a downloaded script, review and trust the source before using the standard Windows unblocking procedure, or contact your administrator if your organization manages execution policies. Do not disable security controls to run Diagnose.

## Run a diagnosis

```powershell
diagnose "Firefox"                 # programs + services, terminal only
diagnose -p "GIMP"                 # programs only
diagnose --program "MyApplication"
diagnose -s "Spooler"              # services only
diagnose --service "Windows Update"
diagnose -p -o md "Firefox"       # terminal + Markdown report
diagnose -p -o txt "GIMP"         # terminal + text report
diagnose -s -o json "Spooler"     # terminal + JSON report
diagnose --help
```

Only `md`, `txt` and `json` are valid values after `-o`. Reports are saved with automatic timestamps in the local `Diagnose/reports/` directory. Without `-o`, nothing is saved except an ephemeral input used during the scan.

After the first scan, a container called **`diagnose`** remains visible in Docker Desktop. It is **Stopped** between scans, starts only for rendering and stops afterward. Rebuilding the image causes the managed container to be refreshed on the next scan. No `docker compose` or `docker down` is needed.

## What does it examine?

Diagnose searches Windows uninstall records, Start menu shortcuts and targets, `App Paths`, programs on `PATH`, common install locations (bounded), active processes, matching registry keys, Store/MSIX packages (current user), and service configuration. It looks for evidence, **not** definitive proof of software health.

Reports present the following sections:

```text
SUMMARY
SOURCE
2. INSTALLS
3. PROCESSES
4. REGISTERS
5. CONCLUSION
6. ISSUES
7. TROUBLESHOOTING
DISCLAIMER
```

`ISSUES` lists possible inconsistencies supported by the scan, and `TROUBLESHOOTING` suggests non-destructive next steps. JSON reports include machine-readable diagnostic data (schema version 5).

## Project files

```text
Diagnose/
├── Dockerfile
├── diagnose.ps1
├── diagnose.bat
├── .dockerignore
├── .gitignore
├── LICENSE
├── README.md
└── reports/
    └── .gitkeep
```

## Troubleshooting setup

- **`diagnose` is not recognized:** reopen your terminal and ensure the directory containing `diagnose.bat` is in your Windows `PATH`.
- **The batch file cannot find the script:** keep `diagnose.bat` beside `diagnose.ps1`, or place it in a sibling `Batchfiles` directory.
- **PowerShell refuses to run the script:** check `Get-ExecutionPolicy -List`. Diagnose does not override execution policy. A downloaded file may require Windows file unblocking after you verify its source; centrally managed policies must be handled by your administrator.
- **Docker image not found:** run one of the two build commands above.
- **Docker unavailable:** start Docker Desktop and select Linux containers.
- **Container name collision:** another container named `diagnose` must be renamed manually; the script will not delete an unrelated container.
- **Report renderer failed:** check `docker logs diagnose`.
- **Some entries missing:** rerun in an elevated terminal when appropriate; some Windows sources require administrator permissions.

## Safety and limitations

The scanner **does not modify Windows**: no registry cleanup, service removal, software uninstallation or automatic repair. A match does not prove an installation works; no match does not prove the software is absent. Portable apps, renamed executables and nonstandard install directories may be missed. The scan is deliberately bounded, not a full filesystem or integrity scan.

Reports may disclose hostnames, usernames, installed software and paths. **Review every report before sharing it.** Actual reports are excluded from Git by `.gitignore`.

## License

Licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See [LICENSE](LICENSE).
