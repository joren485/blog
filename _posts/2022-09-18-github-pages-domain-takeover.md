---
layout: "post"
title:  "An in-depth guide to GitHub Pages (sub)domain takeovers"
date:   "2022-09-18"
author: "Joren Vrancken"
lang: "en"
---

[GitHub Pages](https://pages.github.com/) is a static content hosting service by GitHub. As it is free and integrates with GitHub repositories, it is a popular for hosting blogs, documentation and the like. By default, GitHub Pages content is hosted on `username.github.io`, but users can also conifgure their own domains to host content (e.g. this blog is hosted via GitHub Pages).

As GitHub does not require users to verify ownership over the domains they use, domains configured for GitHub Pages are vulnerable to domain takeovers. This is common knowledge and has been well-documented (e.g. [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz/issues/37), [a HackerOne blog](https://www.hackerone.com/application-security/guide-subdomain-takeovers)).

I started looking into GitHub Pages domain takeover, because I wanted to know how many vulnerable domains there are. It turns out that it is far more widespread than I initially thought. There are tens of thousands of vulnerable domains currently out there, waiting to be hijacked, and they are not that hard to find. Because of this, and because the existing guides/information on GitHub Pages domain takeovers are limited in my opinion, I decided to write a comprehensive blog post to discuss GitHub Pages domain takeovers.

### The Happy Path
Setting up a custom domain for a GitHub Pages domain takes two steps:
1. Pointing DNS records for the domain at the GitHub Pages servers.
2. Adding the domain to the GitHub Pages settings of a GitHub repository.

GitHub has extensive [documentation](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site) on how to configure GitHub Pages and custom domains. There is no point in repeating their documentation here, but I will cover the most important parts and some nuances.

#### Configuring the DNS records of a custom domain
GitHub differentiates between two types of domains:
* Apex domains (i.e. root domains)
* Subdomains

For apex domains, users need to create `A` records pointing to (one of) the following IPv4 addresses:
```
185.199.108.153
185.199.109.153
185.199.110.153
185.199.111.153
```

To support IPv6, users can create `AAAA` records pointing to (one of) the following addresses:
```
2606:50c0:8000::153
2606:50c0:8001::153
2606:50c0:8002::153
2606:50c0:8003::153
```

For subdomains, GitHub recommends creating a `CNAME` record that points to `username.github.io`. `username` does not have to be a user's actuall username, as `*.github.io` has wildcard records that points to the above IP addresses:
```Shell
$ drill -Q A "not-an-existing-user-.github.io"
185.199.111.153
185.199.110.153
185.199.109.153
185.199.108.153
```

#### Adding a domain to a repository
Every repository has a tab for GitHub Pages settings ("Pages"). This tab includes a section that allows users to submit their custom domain. For example, these are the settings for this blog:
![](/assets/github-pages-domain-takeover/github-pages-settings.png)

When a custom domain is added to a repository, GitHub automaically commits a file `CNAME` to the root of the repository with the domain name (the file is also called `CNAME` in case `A` records are used), even if the domain verification fails.

##### Domain Verification
After a user submits a custom domain, GitHub verifies that it is correctly configured and deploys a new GitHub Pages build (with [GitHub Actions](https://github.com/features/actions) workflow). GitHub Pages uses [GitHub Pages Health Check](https://github.com/github/pages-health-check) for verification.

GitHub Pages Health Check performs multiple checks on the DNS records of a domain as well as on the HTTP response headers of the domain to verify it is set up correctly. If the DNS checks fail, `pages-health-check` requires the following HTTP response headers to verify the domain:
* The `Server` header should equal `GitHub.com`.
* The `x-github-request-id` header should be present.

This means that the recommended setup is not required. For example, we can set up subdomains using `A` records, or use reverse proxies (such as Cloudflare).

The verification doesn't even need to succeed for GitHub to start recognizing the domain. For example, I added a domain `asdf.example.com` to a repository with a file `foo` in it. As no `A` or `CNAME` record exist for `asdf.example.com`, it does not pass the verification. But GitHub does recognize it:
```Shell
$ curl -H "Host: asdf.example.com" octocat.github.io/foo
bar
```

### Domain Takeovers
GitHub does not require users to verify domains they submit. This means that anyone can claim a domain that is set up for GitHub Pages, but not actively used. When we visit such a domain, we get the following 404 error:
![](/assets/github-pages-domain-takeover/404-not-site.png)

Domains are vulnerable because of one of two reasons:
1. A domain is unused or abandoned: If a user configured a domain for GitHub Pages but has not used the domain or disconnected the repository they used for the domain, the domain still points to GitHub Pages, but is not actively used.

2. A wildcard DNS record is used to point the domain to GitHub Pages: As Wildcard DNS records (e.g. `*.example.com`) match every subdomain, a (`A` or `CNAME`) wildcard record that points to GitHub Pages means that every subdomain (including multi-level subdomains) point to GitHub Pages. This means that any subdomain (that has not already been claimed) can be taken over by anyone. Because of this, [GitHub explicitly warns users against using wildcard records](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site).

#### Heuristics
Not every domain that points to GitHub Pages and returns a 404 is vulnerable. There are some heuristics that help identify vulnerable domains:
1. The domain should return a 404 status code.
2. The 404 message should read "There isn't a GitHub Pages site here."

    If the domain is used to host a GitHub Pages site, but the file you requested is not found, you get a similar but different 404 error:
    ![](/assets/github-pages-domain-takeover/404-misconfiguration.png)
3. The domain should not already be taken (it can be taken, but active).
  * We can check whether a domain is used by a public GitHub repository, by searching for `example.com filename:CNAME` in GitHub.
  * Unfortunetly, domains can also be used by private repositories. We have no way of knowing this (without trying to take over the domain).
  * If we try to add a taken domain to a repository, we will get the following error:
    ```
    The custom domain `example.com` is already taken. If you are the owner of this domain, check out https://docs.github.com/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages for information about how to verify and release this domain.
    ```

However, these heurisics are not conclusive. Even if all these heuristics pass, we might get the following error when trying to take over a domain:
```
You must verify your domain domain.com before being able to use it. Check out https://docs.github.com/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages for more information.
```

The only way to test whether a domain is vulnerable, is by actually trying to take it over.

#### How to take over a GitHub Pages domain?
Taking over a domain is as simple as adding the domain to a repository you own.

1. Create a repository with some content in the `README.md` that you want to host.
2. Go to the settings of a GitHub repository you own.
3. Go to the Pages tab.
4. Enable GitHub pages (if it is not already enabled).
5. Add the domain in the custom domain section.
  - Optionally enable HTTPs, if availble.
6. Wait for the GitHub Actions workflow to complete the build.
7. Visit the domain to see the `README.md` hosted.

The settings should look something like this:
![](/assets/github-pages-domain-takeover/github-pages-settings.png)

### Countermeasures
The best way to protect yourself against domain takeovers is by not pointing unused domains at GitHub Pages.

[GitHub also allows users to verify that they own a domain](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages). Unfortunately, this verification process has a few flaws:
* The verification only works for a domain and its _immediate_ subdomains. This means that if we verify `example.com`, `example.com` and `sub.example.com` are protected from domain takeovers, but `sub1.sub0.example.com` is not.

    This is why GitHub warns users against using wildcard domains. A wildcard domain is always vulnerable, even if it is verified, because wildcards apply to multiple subdomain levels (e.g. `*.example.com` matches `sub1.sub0.example.com`), but the verification only applies to one subdomain level.

* [GitHub also has a feature that allows users to verify "ownership of domains with GitHub to confirm the identity of organizations owned by your enterprise account"](https://docs.github.com/en/enterprise-cloud@latest/admin/configuration/configuring-your-enterprise/verifying-or-approving-a-domain-for-your-enterprise). These two domain verification methods are completely separate and verifying a domain for one does not verify it for the other.

* Nobody seems to verify their domain for GitHub Pages. I analyzed 2463 domains used to host GitHub Pages. A whopping 17 (_0.7%_) of them verified their domain. Even if my analysis is of by a factor of 10, practically no one is using this.

In the end, It is important to remember that GitHub does not own the domains, the- users do and as such, the responsiblity for protecting them lies on the owner of the domains. The only step that GitHub could take to fully solve this problem is by forcing users to verify their domains ([like GitLab does](https://docs.gitlab.com/ee/user/project/pages/custom_domains_ssl_tls_certification/)).

### Finding vulnerable domains
As I said in the introduction, there are tens of thousands of vulnerable domains. To identify these, we need a way to search for patterns in data on domains. Two great services that provide data on domains are:

* [SecurityTrails](https://securitytrails.com/): SecurityTrails collects that on domains and makes it searchable. For example, DNS history and subdomains. It also provides a reverse DNS search engine that provides all domains that point to a specific IP address. We can use SecurityTrails to identify [domains that point to `185.199.108.153`](https://securitytrails.com/list/ip/185.199.108.153) (and the other GitHub Pages IP addresses).

* [Censys](https://search.censys.io/): Censys collects data on certificates (and IP addresses). We can use it to identify websites that use a certificate requested by GitHub by searching for `(parsed.extensions.subject_key_id: 634e1585565aa49402c21642a4a5979a38025797) AND example.com`.
