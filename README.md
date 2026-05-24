# Wordlists Folder

Place your wordlist files here before running the tool.

## Required Files

| Filename | Download From |
|---|---|
| `subdomains.txt` | https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/subdomains-top1million-5000.txt |
| `directories.txt` | https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/directory-list-2.3-medium.txt |

## Quick Download (Linux / Kali)

```bash
# Download subdomains wordlist
wget -O subdomains.txt https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/subdomains-top1million-5000.txt

# Download directories wordlist
wget -O directories.txt https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/directory-list-2.3-medium.txt
```

## If You Are on Kali Linux

SecLists is already installed. Just copy the files:

```bash
cp /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt subdomains.txt
cp /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt directories.txt
```

## Note

If no wordlist files are found here, the tool will automatically fall back
to its built-in lists and continue running without errors.
