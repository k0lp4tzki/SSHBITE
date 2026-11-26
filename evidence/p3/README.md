# Evidence for package P3 (Delivery)

The image was built and run by the company's compose stack (`stack up --fresh`) from commit 876d573. The stack
runs the top-level `compose.yaml`: the 13 lab hosts plus the `Dockerfile` image (`lab/demo/start.sh`, which does
what docs/install.md asks an admin to do, then runs `sshbite serve`). This workspace has no Docker.

| Asked for | File |
|---|---|
| output of running the image | `container-run.txt`: `id`, `sshbite --version`, `config validate --connect` (pinned entry OK, sudo root), `user add`, a full lab scan with `--ask-sudo-password` (20 access edges, 19 effective, 3 unknown origin, the same as spec 9.3), then `serve` on 0.0.0.0:8722 |
| output of `docker build` | **not available**: the stack builds the image but does not hand the build log to this workspace. The build evidently succeeded (the container runs this commit's image). CI's `image` job keeps the log as an artifact (`docker-build.txt`) |
| `id` in the container shows uid 10001 | first lines of `container-run.txt` |
| login and dashboard served from the container, lab scan DB | `p3-01-login-from-container.png`, `p3-03-dashboard-from-container.png` (more in `/state/screens/p3-*`: login error, heatmap, hosts, phone width). 47 requests, none outside the origin |
| a local run of the CI steps | `ci-local.txt`: ruff, svelte-check, collector lint, actionlint, unit+web (176 passed), e2e against the lab (16 passed, empty snapshot diffs), Playwright (16 passed), checks of the running image |
| docs claims checked on the lab | `docs-lab-checks.txt`: the documented sudoers line and `restrict,port-forwarding` work; plain `restrict` on the entry blocks tunnels. `sudo-mail-lab-test.txt`: which sudo refusals send the "SECURITY information" mail (basis of docs/side-effects.md). `j1-pip-walk.txt`: J1 with the pip install, following the docs |
