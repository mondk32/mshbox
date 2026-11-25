# Security policy

## Status: alpha, unaudited

mshbox is **alpha software and has not been audited** by anyone. It has not been verified on real Windows
by its author at the time of writing (see "Needs verification on real Windows" in the README). It is a
damage-control tool for commands written by an LLM on your own machine. It is **not** a security boundary
against malware or a determined attacker. Do not rely on it to contain hostile code.

## Reporting a vulnerability or bypass

Please report privately first:

* Use GitHub's "Report a vulnerability" (Security tab, private advisory) on this repository, or
* email the maintainer address listed on the repository profile.

Include: Windows version/build, Python version, the exact `mshbox run ...` command line, what you expected
and what happened (for example "file X outside --rw was writable"). Please give us a reasonable window
(suggested: 90 days) before public disclosure. There is no bounty.

## In scope

* Writes/reads outside granted paths, network access without `--net`, children surviving timeout.
* ACEs or AppContainer profiles left behind after a normal run, a crash, or `mshbox cleanup`.
* Any case where the command runs even though sandbox setup failed (this must never happen).
* Over-broad grants (for example a grant that exposes `~/.ssh` through inheritance).

## Out of scope

* Anything reachable through a path you explicitly granted with `--rw` / `--ro`.
* Attacks that need administrator rights, kernel exploits, or sandbox-escape vulnerabilities in Windows itself.
* Surrogate-process escapes (asking an unsandboxed service to act on the sandbox's behalf) are not claimed to be covered.
