# Releasing cfr2

Releases are built locally with GoReleaser; nothing secret lives in GitHub Actions.

1. `go test ./...` and the checks: `gitleaks detect --source .` (history) and
   `gitleaks detect --no-git --source .` (tree).
2. Tag: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`
3. Build and publish (GitHub release + Homebrew formula in j4y-w4lk3r/homebrew-cfr2):

   ```sh
   GITHUB_TOKEN=$(gh auth token) HOMEBREW_TAP_GITHUB_TOKEN=$(gh auth token) \
     go run github.com/goreleaser/goreleaser/v2@latest release --clean
   ```

   The token only lives in the environment of that one command.
4. AUR (on a machine with the AUR ssh key and makepkg): `arch/aur-publish.sh X.Y.Z`
5. Check: `brew install j4y-w4lk3r/cfr2/cfr2` on macOS, `yay -S cfr2-bin` on Arch.
