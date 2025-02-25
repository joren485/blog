---
layout: "post"
title:  "Substack Domain Takeover"
date:   "2025-02-25"
author: "Joren Vrancken"
lang: "en-US"
---

[Substack](https://substack.com/) is a popular blogging platform. It allows writers to easily create their own personal blog, with payments, comments, analytics and other advanced features. Substack empowers writers to customize their blogs by adding a custom domain.

In this blog, we will talk about an edge case that allows an attacker to take over inactive Substack blog custom domains.

### Introduction

When you create a blog on substack, it will be available on the `<username>.substack.com` subdomain. If writers want their blog to look a bit more professional, they can add a custom domain. For example, instead of having your blog named `https://michaelshellenberger.substack.com`, you can use `https://www.public.news/`.

To set up a [custom domain on Substack](https://support.substack.com/hc/en-us/articles/360051222571-How-do-I-set-up-my-custom-domain-on-Substack), a customer needs to create a `CNAME` record pointing from their domain to `target.substack-custom-domains.com`[^0] and adding the domain to blog settings:

![](/assets/substack-domain-takeover/setup.png)

Before a customer is allowed to use a custom domain, however, they first have to pay a one-time __$50__ fee.

Behind the scenes, Substack uses [Cloudflare for SaaS](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/) to manage most of the custom domain heavy lifting. Cloudflare for SaaS allows companies to easily route customer domains to company infrastructure.
When a customer adds a custom domain to their Substack blog, Substack will add the domain to their Cloudflare for SaaS account and Cloudflare will route requests to the custom domain to Substack. Whenever someone visits the custom domain, the request is sent to Substack. Substack then matches the requested domain to a blog to serve to the visitor.

### The Edge Case
Software that supports setting up a custom domain, is a great target for domain takeover attacks [^1], a type of attack where an attacker is able to control the content that is served on a victim domain.

When a customer wants to stop using a custom domain for a Substack blog (e.g. because they want to stop publishing the blog), they will have to manually remove the `CNAME` record. But what if someone forgets to remove the `CNAME` record?

When a `CNAME` record exists for a custom domain and the domain is linked to a Substack blog, Substack will serve the blog without issue. However, if the `CNAME` record exists, but the domain is not linked to Substack blog, the domain will not be added to the Cloudflare for SaaS account of Substack and Cloudflare will not know where to route requests to the domain. This will result in an error from Cloudflare:

| ![](/assets/substack-domain-takeover/error-1001.png) | ![](/assets/substack-domain-takeover/error-1014.png) |
| :--: | :--: |
| A Cloudflare 1001 error for domains that are not managed by Cloudflare. | A Cloudflare 1014 error for domains that are managed by Cloudflare. |

### Taking over a subdomain
You may have noticed that Substack does not actually authenticate that a domain is owned by a customer when the customer adds it to their blog. The domain just needs a `CNAME` record that points to `target.substack-custom-domains.com`.

This means that if someone accidentally adds a `CNAME` record to their domain, but does not add it to a Substack blog, anyone can add the domain to a Substack blog (they will also have to pay the $50 fee).

Let's look at `denver.therollup.co`, a domain that I do not have any association with. It has the correct `CNAME`:
```bash
$ drill denver.therollup.co
...
;; ANSWER SECTION:
denver.therollup.co.	253	IN	CNAME	target.substack-custom-domains.com.
target.substack-custom-domains.com.	21	IN	A	172.64.151.232
target.substack-custom-domains.com.	21	IN	A	104.18.36.24
...
```

But it is not actually added to a blog:
![](/assets/substack-domain-takeover/denver.rollup.co-1001.png)

This allows anyone to add the domain to their own Substack blog and serve any content they want:
![](/assets/substack-domain-takeover/denver.therollup.co-takeover.png)

### Wildcard domains
The above attack only works on domains that are no longer active. However, if someone sets up a wildcard `CNAME` record (e.g. `*.example.com` has a `CNAME` to `target.substack-custom-domains.com`), every domain under the wildcard record is vulnerable to a domain takeover.

### Discussion
Using to DNS databases (such as [SecurityTrails](https://securitytrails.com/)) I found 16925 custom domains (i.e. domains that have a `CNAME` pointing to `target.substack-custom-domains.com`). Of these, 1426 are not actually connected to a Substack blog, and as such, vulnerable to domain takeover. More than 8% vulnerable is a significant portion. Of these 1426 domains, 11 domains are wildcard domains.

This is not a vulnerability in Substack, as Substack does not own or manage these domains. However, Substack could solve this problem forever by requiring customers to authenticate the domains they own ([Cloudflare for SaaS support this](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/domain-support/hostname-validation/pre-validation/)). This would require a bit more configuration on the customers side, but would ultimately mean that domain takeover attacks are not possible anymore.

However, Substack has another measure in place that will prevent some domain takeover attacks: the $50 fee to enable custom domains on a blog. $50 will not stop a motivated attacker, but it will prevent an attacker from taking over a domain just for fun. It is unclear whether Substack deliberately implemented the $50 fee as some sort of behavioral security measure, but it does have that effect.

### Mitigation
If a domain has a `CNAME` record pointing to `target.substack-custom-domains.com`, either add it to a blog or remove the `CNAME` record. And never point a wildcard domain to `target.substack-custom-domains.com`.

---

[^0]: It is also possible for customers to [set up a redirect from a root domain to a subdomain](https://support.substack.com/hc/en-us/articles/360051222691-Can-I-use-my-root-domain-without-www-or-another-subdomain-on-Substack).

[^1]: The GitHub repo [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) keeps track of many SaaS products that allow for sudomain takeover attacks.
