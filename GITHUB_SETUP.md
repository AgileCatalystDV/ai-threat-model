# GitHub Repository Setup Guide

## Stap 1: Git Repository Initialiseren

```bash
cd /Users/dirkverstraete/ai-threat-model

# Git initialiseren
git init

# Alle bestanden toevoegen
git add .

# Eerste commit
git commit -m "Initial commit: AI Threat Model CLI + API + Frontend"
```

## Stap 2: GitHub Repository Aanmaken

### Optie A: Via GitHub Website (Aanbevolen)

1. Ga naar https://github.com/new
2. Repository naam: `ai-threat-model` (of kies je eigen naam)
3. Beschrijving: "Open-source threat modeling tool for AI-native systems"
4. **Public** of **Private** (jouw keuze)
5. **NIET** "Initialize with README" (we hebben er al een)
6. Klik "Create repository"

### Optie B: Via GitHub CLI (als je `gh` hebt geïnstalleerd)

```bash
gh repo create ai-threat-model --public --description "Open-source threat modeling tool for AI-native systems"
```

## Stap 3: Remote Toevoegen en Pushen

### Optie A: HTTPS (Eenvoudigste - aanbevolen voor beginners)

```bash
# Remote toevoegen (vervang USERNAME met jouw GitHub username)
git remote add origin https://github.com/USERNAME/ai-threat-model.git

# Branch naam instellen
git branch -M main

# Pushen naar GitHub
git push -u origin main
```

**Als GitHub vraagt om authenticatie:**
- Gebruik een **Personal Access Token** (niet je wachtwoord)
- Maak er een aan: https://github.com/settings/tokens
- Scopes: `repo` (alle repo permissies)

### Optie B: SSH (Aanbevolen voor developers)

#### SSH Key Aanmaken (als je die nog niet hebt):

```bash
# Check of je al SSH keys hebt
ls -al ~/.ssh

# Als je geen id_ed25519 of id_rsa hebt, maak een nieuwe aan:
ssh-keygen -t ed25519 -C "your_email@example.com"

# Of gebruik RSA als ed25519 niet werkt:
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

# Volg de prompts (Enter drukken voor default locatie, wachtwoord optioneel)
```

#### SSH Key Toevoegen aan GitHub:

```bash
# Kopieer je publieke key
cat ~/.ssh/id_ed25519.pub
# Of voor RSA:
cat ~/.ssh/id_rsa.pub

# Kopieer de output (begint met ssh-ed25519 of ssh-rsa)
```

1. Ga naar https://github.com/settings/keys
2. Klik "New SSH key"
3. Titel: "MacBook" (of wat je wilt)
4. Key: Plak de gekopieerde key
5. Klik "Add SSH key"

#### Test SSH Connectie:

```bash
ssh -T git@github.com
# Je zou moeten zien: "Hi USERNAME! You've successfully authenticated..."
```

#### Remote Toevoegen met SSH:

```bash
# Remote toevoegen (vervang USERNAME met jouw GitHub username)
git remote add origin git@github.com:USERNAME/ai-threat-model.git

# Branch naam instellen
git branch -M main

# Pushen naar GitHub
git push -u origin main
```

## Stap 4: Verificatie

Ga naar `https://github.com/USERNAME/ai-threat-model` en check of alle bestanden er zijn!

## Toekomstige Updates

```bash
# Wijzigingen toevoegen
git add .

# Committen
git commit -m "Beschrijving van je wijzigingen"

# Pushen
git push
```

## Handige Git Commands

```bash
# Status checken
git status

# Wijzigingen bekijken
git diff

# Commit geschiedenis
git log --oneline

# Laatste commit ongedaan maken (lokaal)
git reset --soft HEAD~1
```

## Troubleshooting

### "Permission denied" bij SSH
- Check of je SSH key is toegevoegd aan GitHub
- Test met: `ssh -T git@github.com`

### "Authentication failed" bij HTTPS
- Gebruik Personal Access Token, niet je wachtwoord
- Maak nieuwe token: https://github.com/settings/tokens

### "Repository not found"
- Check of de repository naam klopt
- Check of je de juiste username gebruikt

## GitHub Repository Settings

Na het pushen, overweeg deze settings:

1. **Description**: Voeg een goede beschrijving toe
2. **Topics**: Voeg tags toe zoals `threat-modeling`, `security`, `ai`, `llm`, `owasp`
3. **Website**: Als je later een demo hebt
4. **License**: Apache-2.0 (staat al in pyproject.toml)

## README Verbeteren

Je README.md is al goed, maar je kunt toevoegen:
- Badges (build status, license, etc.)
- Screenshots van de UI
- Demo link (als je die hebt)
- Contributing guidelines

Veel succes! 🚀
