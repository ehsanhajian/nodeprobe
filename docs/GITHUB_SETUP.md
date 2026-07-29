# GitHub setup

Follow these steps to connect this repository to GitHub.

## 1. Add SSH key to GitHub

A deploy key pair was generated on this machine (if not already present):

```bash
cat ~/.ssh/id_ed25519_github.pub
```

1. Open [GitHub → Settings → SSH and GPG keys](https://github.com/settings/keys)
2. Click **New SSH key**
3. Paste the public key
4. Save

Verify:

```bash
ssh -T git@github.com
```

Expected: `Hi <username>! You've successfully authenticated...`

## 2. Configure git identity (once per machine)

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

## 3. Create the remote repository

### Option A — GitHub CLI (recommended)

```bash
cd /home/ubuntu/dapptility
gh auth login
gh repo create dapptility --private --source=. --remote=origin --push
```

Use `--public` instead of `--private` if you prefer an open repo.

### Option B — GitHub website

1. Create a new repository named `dapptility` at [github.com/new](https://github.com/new)
2. Do **not** initialize with README (this repo already has one)
3. Add remote and push:

```bash
cd /home/ubuntu/dapptility
git remote add origin git@github.com:<ORG_OR_USER>/dapptility.git
git push -u origin main
```

## 4. Branch protection (after first push)

On GitHub: **Settings → Branches → Add rule** for `main`:

- Require a pull request before merging
- Require status checks to pass (`CI / Repository checks`)

## 5. Optional — GitHub secrets (later)

When CI needs credentials:

- `Settings → Secrets and variables → Actions`

Do not commit secrets. Use `.env.example` for local development placeholders only.
