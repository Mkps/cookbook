@echo off
REM Script de lancement - Version Radar avec API (Windows)

echo.
echo ================================================
echo  VibeStream Radar - Analyse avec API Scorton
echo ================================================
echo.

REM Vérifier si on est dans le bon répertoire
if not exist "main_radar.py" (
    echo [ERREUR] Veuillez executer ce script depuis le dossier vibestream_radar\
    echo    cd vibestream_radar
    echo    run_radar.bat
    pause
    exit /b 1
)

REM Créer les fichiers __init__.py si manquants (fix pour le module import)
echo [INFO] Verification de la structure...
for %%d in (api analyzers reports utils) do (
    if not exist "%%d\__init__.py" (
        echo    [OK] Creation de %%d\__init__.py
        echo """Package %%d""" > "%%d\__init__.py"
    )
)
echo.

REM Vérifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe ou pas dans le PATH
    pause
    exit /b 1
)

echo [OK] Python detecte
echo.

REM Vérifier les arguments
if "%1"=="" (
    echo [ERREUR] Aucune cle API fournie!
    echo.
    echo Utilisation:
    echo    run_radar.bat API_KEY URL
    echo.
    echo Exemple:
    echo    run_radar.bat sk-abc123... https://example.com
    echo.
    echo Obtenez votre cle sur: https://radar.scorton.tech/ui/
    pause
    exit /b 1
)

if "%2"=="" (
    echo [ERREUR] Aucune URL fournie!
    echo.
    echo Utilisation:
    echo    run_radar.bat API_KEY URL
    pause
    exit /b 1
)

REM Installer les dépendances
echo Installation des dependances...
pip install -r requirements.txt --break-system-packages
echo.

REM Lancer l'analyse
echo Analyse de: %2
echo.

python main_radar.py --api-key %1 --url %2 --save-raw --output reports

echo.
echo [TERMINE] Ouvrez le rapport HTML dans reports\
echo.
pause
