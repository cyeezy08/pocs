# Contributing

Thanks for looking. This is a small project maintained by one person, so here
is what is actually useful and what will go unanswered.

## What gets a fast response

**A bug with a reproduction.** The command, the input, what you expected, what
happened. If it needs live data, say what you are authorised to query and what
the target is.

**A scoring result you think is wrong.** This is the most valuable report this
project gets. The tool exists to produce an explainable number, so "this asset
scored 4 and I expected 90" is the interesting case. Include the score output
verbatim, the asset, and which signals you expected to fire.

**A missing or wrong signal.** CVSS, EPSS, and CISA KEV are three separate
inputs. If a feed changed shape, or a CVE is being matched to the wrong asset,
that is a correctness bug and it is worth reporting with the CVE and the asset.

**A false claim of completeness.** If the tool reported a clean result while a
feed was stale, empty, or silently failing to load, that is the bug class this
project is against. Include the output.

## What will go unanswered

Feature requests that are really "make this a platform". Requests to add a
dashboard. Anything with speculation and no output.

## Ground rules

**Passive by default.** Every feed this tool reads is public metadata: NVD,
EPSS, CISA KEV. If a change would make it send traffic anywhere else, that needs
to be opt-in and documented.

**Authorisation is on you.** Only run this against assets you own or have
written permission to test. Do not paste real customer asset inventories into
an issue.

**Do not report vulnerabilities in this tool to a third party.** Report them
here first. There is no bug bounty on this org.

**Scores stay explainable.** If you add a signal, it must appear in the
explanation output, not just move the number. A score nobody can audit is a
number nobody should act on, which is the entire premise of this project.

## Working on it

Python 3.10 or newer:

```bash
git clone https://github.com/leviathan-offsec/leviathan-core.git
cd leviathan-core
pip install -e '.[dev]' pytest
pytest -q
```

Tests that fail CI will fail for you locally too. Open the PR anyway if you are
stuck, and say what is stuck.

## Commit messages

Say what changed and why. The `why` is the part that matters six months later.

## Security reports

Not via a public issue. See [SECURITY.md](SECURITY.md).
