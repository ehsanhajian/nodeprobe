# GitHub setup

Repository is connected and active.

| Item | Value |
|---|---|
| URL | https://github.com/ehsanhajian/dapptility |
| Remote | `git@github.com:ehsanhajian/dapptility.git` (SSH) |
| Default branch | `main` |
| Issues | https://github.com/ehsanhajian/dapptility/issues |

## SSH authentication

Verify access:

```bash
ssh -T git@github.com
```

Expected: `Hi <username>! You've successfully authenticated...`

If push fails with HTTPS credential errors, ensure the remote uses SSH:

```bash
cd /home/ubuntu/dapptility
git remote set-url origin git@github.com:ehsanhajian/dapptility.git
git push origin main
```

## Git identity

Configure once per machine if not already set:

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

## Push workflow

```bash
cd /home/ubuntu/dapptility
git add -A
git commit -m "Your message"
git push origin main
```

For feature branches:

```bash
git checkout -b feature/my-change
git push -u origin feature/my-change
gh pr create
```

## CI

GitHub Actions runs scanner tests on push/PR to `main`:

- Workflow: `.github/workflows/ci.yml`
- Job: `Scanner tests` (`pytest -q` in `scanner/`)

## Branch protection (recommended)

On GitHub: **Settings → Branches → Add rule** for `main`:

- Require a pull request before merging
- Require status checks to pass (`Scanner tests`)

## Secrets (later)

When CI or deployment needs credentials:

- `Settings → Secrets and variables → Actions`

Do not commit secrets. Use `.env.example` for local development placeholders only.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for scanner setup, architecture, and milestone status.
