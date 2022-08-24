---
layout: "post"
title:  "An in-depth guide to Github Pages (sub)domain takeovers"
date:   "2022-07-17"
author: "Joren Vrancken"
lang: "en"
---

<!--
Ideas:
- Goed naar de gevonden domeinen kijken
- Is een link in de description genoeg om verificatie te vereisen?
-->

<!--
Blog ideas:
- Code toevoegen
- Talk about open source funding
  - If any of these projects had a Hackerone, these bugs would have been found in minutes
-->

<!--
Reported to:
- Augur: turbo-docs.augur.sh
- Podman: *.podman.io
- PyYaml: *.pyyaml.org
- Watchman: *.containrrr.dev
- Cryptoswift: *.cryptoswift.io
- Animate.css: *.animate.style
- kamranahmedse/developer-roadmap: *.roadmap.sh
  - Email found on his Youtube page.
- Playwright: *.playwright.dev
  - via MSRC

- Github, via Hackerone
-->

Domain takeovers are a common vulnerability. Just google "domain takeover hackerone" and you will find many examples. Most (if not all) services that let you publish arbitrary content on a custom domain, will have some type of domain takeover vulnerabilities. One of the most common services for domain takeovers to happen on is Github Pages, the static content hosting service of Github.

Github Pages allows users to publish content at `<username>.github.io` or at a custom domain. The latter option requires some DNS setup.

There are many blog posts, Github repositories, Hackerone reports, etc. explaining the issue. This makes it surprising that this issue is still so prevalent.

In a few hours after started looking into Github Pages domain takeovers, I had found hundreds of vulnerable domains. Most of these are, of course, used to host forgotten blogs and documentation for obscure Python packages. However, there were also many domains that were used to host the blogs and documentation of popular open source software. I found tens of domains used by Github repositories with thousands of stars. Some even having tens of thousands and one having multiple hunderds of thousands of stars (which seems to make it one of [the ten most popular repositories](https://github.com/EvanLi/Github-Ranking)).

No one has ever checked the most popular repositories for this easy to exploit vulnerablity? That suprises me a lot.

### Why should you care about domain takeovers?
Let's say you are the maintainer of a popular Javascript package, ExampleJS. And you host the documentation and some promotinal material for ExampleJS on `examplejs.io` using Github Pages. An attacker notices that you have incorrectly configured Github Pages and hijackes `downloads.examplejs.io`. The attacker publishes a phising page on this domain that looks like it is used to distribute the newest version of ExampleJS, but in reality, it is used to spread malware. Suddenly a lot of your community channels (be it, Github Issues, Discord, IRC, Twitter, etc.) start getting flooded with spam pointing people to download the newest version of ExampleJS at `downloads.examplejs.io`. Potentially thousands of ExampleJS users are infected through a domain that you own.

This is no bueno.

### The Happy Path

https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site

Types of Github pages domain setups:
- Root/apex domains: A records
- Subdomains: CNAME records

A `CNAME` file is created for both types.

```
185.199.108.153
185.199.109.153
185.199.110.153
185.199.111.153
```

```
2606:50c0:8000::153
2606:50c0:8001::153
2606:50c0:8002::153
2606:50c0:8003::153
```


### Types of Domain Takeover

#### 404

Heuristics:
- 404 status code
- "There isn't a GitHub Pages site here." in response
- No existing CNAME file on github with the domain
  - Query on Github: `domain.com filename:CNAME`
  - Else you get the following error: ```You must verify your domain domain.com before being able to use it. Check out https://docs.github.com/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages for more information. ```

The heuristics are not decisive. It is still possible to get an error, even if all heuristics pass.
- ```The custom domain `domain.com` is already taken. If you are the owner of this domain, check out https://docs.github.com/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages for information about how to verify and release this domain.```

#### Wildcard


#### Finding domains


#### Countermeasures

1.  The single best thing you can do is [to verify your domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages). This is a feature implemented by Github that allows users and organizations to tell Github that they own a domain (and its subdomains) and no one but them is allowed to publish content on it. It is as simple as adding a `TXT` record to your domains DNS records.

  ##### Do people actually use the domain verification feature?
  No, they do not.

  I analyzed 2463 domains used to host Github Pages. A whopping 17 (_0.7%_) of them seemed to have verified their domain with a `TXT` record. Even if my analysis is of by a factor of 10, practically no one used this.

  To be clear, verifying your domain at Github completely solves Github Pages domain takeovers.

2. Publish a security policy or responsible disclosure aggreement.

  At the beginning of this blog I said I found hundreds of vulnerable domains, with a significant amount being used by actually popular projects. I tried to notify as many of the most popular projects that they are vulnerable. However, I cannot identify, find the contact for and notify hundreds of projects.

  Github allows maintainers [to add a security policy to their repositories](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository). This really helped me, because it gave me instructions on how to reach the right people within two clicks.

  For some projects, I was simply not able to find a way to privately message a maintainer. I would have liked to notify them, but unfortunately it was not possible.
