---
layout: "post"
title:  "Hijacking Arch Linux Packages by Repo Jacking GitHub Repositories"
date:   "2023-04-10"
author: "Joren Vrancken"
lang: "en-us"
---

Last year, we published [a blog post]({% post_url 2022-10-23-aur-packages-expired-domains %}) discussing an attack where a malicious actor hijacks [Arch User Repository](https://aur.archlinux.org/) (AUR) vulnerable packages by registering expired domains.

However, most AUR packages do not use files hosted on some random domain, but files hosted on large software repositories, such as [PyPI](https://pypi.org/), the [npm Registry](https://www.npmjs.com/) and [GitHub](https://github.com/). In fact, if we look at the top 10 used domains in the AUR, we find that GitHub makes up the vast majority of them:

| # | Domain | Number of Sources |
| :---: | :--- | :--- |
| 1 | `github.com` | 54859 |
| 2 | `githubusercontent.com` | 3587 |
| 3 | `sourceforge.net` | 2973 |
| 4 | `pythonhosted.org` | 2826 |
| 5 | `bioconductor.org` | 2237 |
| 6 | `gitlab.com` | 2061 |
| 7 | `r-project.org` | 1779 |
| 8 | `npmjs.org` | 1569 |
| 9 | `cpan.org` | 1492 |
| 10 | `gnu.org` | 1062 |

GitHub has the top two spots, with nearly sixty thousand sources. This makes GitHub repositories a good target when looking for AUR packages to hijack. If we are able to take over an upstream GitHub repository used by an AUR package, we might also be able to take over the package itself.

Repo jacking is an attack on GitHub repositories, where attackers are able to hijack GitHub repositories by reregistering previously used usernames.

In this blog post, we discuss how many AUR packages (use GitHub packages that) are vulnerable to repo jacking attacks.

### Hijacking Packages using Repo Jacking
_For a detailed explanation of repo jacking attacks and mitigations against such attacks, please read our previous blog post [Hijacking GitHub Repositories by Deleting and Restoring Them]({% post_url 2022-12-04-gitub-popular-repository-namespace-retirement-bypass %})._

In short, when a GitHub user renames their account, others are able to reregister the original username and create repositories previously created by the original user. This effectively hijacks the repositories of the original user, without their knowledge. This is called repo jacking.

There are two distinct scenarios that make a GitHub repository vulnerable to a repo jacking attack:
1. A GitHub user changes their username: In this case all repositories of the user still exist, but under a different owner. The old repository name will redirect to the new repository name, until it is recreated by another user. For example, `victim/python-package` will be redirected `fancy-victim/python-package` when `victim` changes their name to `fancy-victim`, until a new user registers the `victim` account and creates the `victim/python-package` repository.

2. A GitHub user deletes their account: In this case all repositories of the user do no longer exist anymore and referencing them (e.g. during installation) will result in an error.

In the first scenario, any downstream packages that use the vulnerable GitHub repository will be transparently redirected to the new repository. From an attacker's perspective, this is ideal, because it disincentivizes package maintainers from changing to the new repository name, increasing the chance that packages will use the old, vulnerable repository name.

The second scenario is less useful to attackers, because this will break any downstream packages trying to use the deleted repository, making it more likely that package maintainers will notice that the GitHub repository does not exist anymore.

If an attacker is able to find a package that uses a GitHub repository vulnerable to repo jacking, they are able to hijack the underlying package, by publishing arbitrary malicious files in the vulnerable repository.

It should be noted that the impact of a such an attack depends on what happens to the sources during the installation process. For example, if a package only clones a GitHub repository to copy the `LICENSE` file, an attacker will only be able to change the `LICENSE` file.

#### An Example of an Attack

Let's look at an example of how such an attack would work. We will look at the [`blackmagic`](https://archlinux.org/packages/community/x86_64/blackmagic/) package, which has the following `PKGBUILD` file:

```bash
pkgname=blackmagic
pkgver=1.8.2
pkgrel=1
pkgdesc='In application debugger for ARM Cortex microcontrollers'
arch=('x86_64')
url='https://github.com/blacksphere/blackmagic'
license=('GPL')
depends=('libusb' 'libftdi' 'libhidapi-libusb.so')
makedepends=('git' 'hidapi' 'python')
source=("git+$url#tag=v$pkgver")
sha512sums=('SKIP')

prepare() {
  sed -i 's| -Werror||' $pkgname/src/Makefile
}

build() {
  cd $pkgname

  make PROBE_HOST=hosted
}

package() {
  cd $pkgname

  install -Dm 755 src/blackmagic "$pkgdir"/usr/bin/blackmagic

  install -Dm 644 driver/99-blackmagic.rules "$pkgdir"/usr/share/solaar/udev-rules.d/99-blackmagic.rules
}
```

As we can see, during the installation of `blackmagic`, `makepkg` will clone and install the `blacksphere/blackmagic` GitHub repository. However, if we got to `https://github.com/blackmagic-debug/blackmagic`, we are redirected to `https://github.com/blackmagic-debug/blackmagic`. The owners of the `blacksphere` GitHub account have renamed their account to `blackmagic-debug`.

If we were to register the `blacksphere` GitHub account and create a new `blacksphere/blackmagic` repository, we will have full control over what is installed by the `blackmagic` package. We can publish arbitrary files, and they will be compiled by `make PROBE_HOST=hosted` when installing the `blackmagic` package.

**Please Note:** _I am in no way affiliated with the previous owners of the `blacksphere` GitHub account. I registered the `blacksphere` GitHub account, to confirm the attack is possible and to prevent others from exploiting it._

### Finding Vulnerable AUR Packages
_If you want to know more about the [Arch Build System](https://wiki.archlinux.org/title/Arch_Build_System) and how we got data of all packages, please read the [first post]({% post_url 2022-10-23-aur-packages-expired-domains %})._

To find vulnerable packages in the AUR, we will need a list of GitHub repositories used by each package. We can create such a list by looking for GitHub URLs in the [`.SRCINFO`](https://wiki.archlinux.org/title/.SRCINFO) file of each package. This gives us 24899 unique GitHub users with 42559 unique repositories. To find repositories vulnerable to repo jacking, we need to identify the users that do not exist anymore.

GitHub has a [REST API](https://docs.github.com/en/rest) and a [GraphQL API](https://github.com/graphql), that we can use to find which users do not exist anymore.

We use the following simple GraphQL query to check if a GitHub user still exists:
```
query ($owner: String!) {
  repositoryOwner(login: $owner) {
    login
  }
}
```

Unfortunately, for simple queries like this, the REST API and the GraphQL API have the same [rate limit](https://docs.github.com/en/graphql/overview/resource-limitations): 5000 requests per hour.

After a few hours, we found 439 GitHub users that do not exist anymore. These users have 529 GitHub repositories that are used by packages. When we check whether a repository exist, we get one of two outcomes:

1. The repository exists: this means that the user was renamed and GitHub set up a redirect from the old repository name to the new repository name. Any packages referencing the repository will still work.

2. The repository does not exist anymore: the user was deleted and any packages referencing the repository are broken.

From an attacker's perspective, the first scenario is far more interesting, because packages that use existing GitHub repositories can still be installed.

We again use the GraphQL API to check which repositories exist:
```
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    owner {
      login
    }
    name
    stargazerCount
  }
}
```

The API tells us that 433 repositories exist and the other 96 repositories do not.

### Checksums and PGP Keys
Can we hijack all the packages that use these 529 vulnerable repositories? Yes, but the impact depends on whether a package uses integrity verification.

Packages can provide either hashes or PGP signatures for source files that are checked during installation. Consequently, if an attacker succeeds in hijacking a GitHub repository and publishes malicious files to be installed by a downstream, the files will not pass the integrity verification checks of the package (i.e. the installation will fail). This is, of course, still an undesirable situation from a user's perspective, because it breaks the installation of the package (and any package that depend on it).

It is important to note that VCS sources (e.g. Git sources) cannot use these verification checks, as ["the sources are not static"](https://wiki.archlinux.org/title/VCS_package_guidelines). VCS sources can specify commit hashes and PGP signed revisions for integrity verification, but these are not commonly used. This makes repo jacking attacks more interesting, because many GitHub sources will not have integrity verification.

### Putting It All Together
To summarize, we have two types of vulnerable packages:
1. Vulnerable packages that use integrity verification.
2. Vulnerable packages that do not use integrity verification.

These vulnerable packages, can use two types of vulnerable GitHub repositories as sources:
1. Repositories that exist (i.e. redirect to the repository under a different user).
2. Repositories that do not exist anymore.

Combing these, we get four types of vulnerable packages:

|                             | **Integrity verification** | **No integrity verification** |
| **Repository exists**       | 180 packages (type **_11_**) | 276 packages (type **_21_**) |
| **Repository doesn't exist**| 44 packages (type **_12_**) | 46 packages (type **_22_**) |

_There is some overlap, because some packages use integrity verification for some GitHub sources, but not for others._

* Packages of type **_11_** and **_12_** are vulnerable to denial of service attacks.
  * As packages of type **_12_** are broken already, a denial of service attack will have no impact.
* Packages of type **_21_** and **_22_** are vulnerable to full hijack attacks, where an attacker can make them install arbitrary files.
* Packages of type **_21_** are most interesting to attackers, because these packages are currently working and thus more likely to be used by users.

### Are these packages actually used by users?
Focussing on the more interesting packages (i.e. the 276 type **_21_** packages), we would like to know whether these are packages that are actually used by users (i.e. where an attack would have an actual impact).

#### Top 10 Vulnerable Packages Sorted by AUR Popularity

The AUR has its own measure of package popularity. Users can vote for their favorite packages and [the AUR computes the popularity based on the following formula](https://aur.archlinux.org/packages):

> Popularity is calculated as the sum of all votes with each vote being weighted with a factor of 0.98 per day since its creation.

We can sort the vulnerable packages by their popularity score, to find the ten most popular vulnerable packages:

| # | Package | GitHub Repository | Popularity |
| :---: | :--- | :--- |
| 1 | [`libinput-three-finger-drag`](https://aur.archlinux.org/packages/libinput-three-finger-drag) | [jasper-van-bourgognie/libinput](https://github.com/jasper-van-bourgognie/libinput) | 1.742225 |
| 2 | [`lxqt-plugin-wingmenu-git`](https://aur.archlinux.org/packages/lxqt-plugin-wingmenu-git) | [slidinghotdog/plugin-wingmenu](https://github.com/slidinghotdog/plugin-wingmenu) | 0.48887 |
| 3 | [`sddm-slice-git`](https://aur.archlinux.org/packages/sddm-slice-git) | [radrussianrus/sddm-slice](https://github.com/radrussianrus/sddm-slice) | 0.453811 |
| 4 | [`nimble-git`](https://aur.archlinux.org/packages/nimble-git) | [nimrod-code/nimble](https://github.com/nimrod-code/nimble) | 0.449599 |
| 5 | [`deadbeef-jack-git`](https://aur.archlinux.org/packages/deadbeef-jack-git) | [alexey-yakovenko/jack](https://github.com/alexey-yakovenko/jack) | 0.208647 |
| 6 | [`ocaml-ocplib-simplex-git`](https://aur.archlinux.org/packages/ocaml-ocplib-simplex-git) | [ocamlpro-iguernlala/ocplib-simplex](https://github.com/ocamlpro-iguernlala/ocplib-simplex) | 0.076932 |
| 7 | [`xpwn-nyuszika7h-git`](https://aur.archlinux.org/packages/xpwn-nyuszika7h-git) | [nyuszika7h/xpwn](https://github.com/nyuszika7h/xpwn) | 0.066517 |
| 8 | [`gogh-git`](https://aur.archlinux.org/packages/gogh-git) | [mayccoll/gogh](https://github.com/mayccoll/gogh) | 0.057908 |
| 9 | [`hardcode-tray-git`](https://aur.archlinux.org/packages/hardcode-tray-git) | [bil-elmoussaoui/hardcode-tray](https://github.com/bil-elmoussaoui/hardcode-tray) | 0.044694 |
| 10 | [`faustus-hyperkvm-dkms-git`](https://aur.archlinux.org/packages/faustus-hyperkvm-dkms-git) | [hyper-kvm/faustus](https://github.com/hyper-kvm/faustus) | 0.043527 |

These popularity scores tell us that these packages are definitely used, but not by many. For comparison, the highest score of all packages in the AUR is 38.75.


#### Top 10 Vulnerable Packages Sorted by GitHub stars

Another metric that is a proxy for actual usage, is the number of GitHub stars of the upstream GitHub repositories.

| # | Package | GitHub Repository | Stars |
| :---: | :--- | :--- |
| 1 | [`linux-dash-git`](https://aur.archlinux.org/packages/linux-dash-git) | [afaqurk/linux-dash](https://github.com/afaqurk/linux-dash) | 10009 |
| 2 | [`mosaic-git`](https://aur.archlinux.org/packages/mosaic-git) | [mosaic-org/mosaic](https://github.com/mosaic-org/mosaic) | 8726 |
| 3 | [`open3d`](https://aur.archlinux.org/packages/open3d) | [intel-isl/open3d](https://github.com/intel-isl/open3d) | 7594 |
| 4 | [`open3d-git`](https://aur.archlinux.org/packages/open3d-git) | [intel-isl/open3d](https://github.com/intel-isl/open3d) | 7594 |
| 5 | [`gogh-git`](https://aur.archlinux.org/packages/gogh-git) | [mayccoll/gogh](https://github.com/mayccoll/gogh) | 7322 |
| 6 | [`python-django-debug-toolbar-git`](https://aur.archlinux.org/packages/python-django-debug-toolbar-git) | [django-debug-toolbar/django-debug-toolbar](https://github.com/django-debug-toolbar/django-debug-toolbar) | 7245 |
| 7 | [`gateway`](https://aur.archlinux.org/packages/gateway) | [mozilla-iot/gateway](https://github.com/mozilla-iot/gateway) | 2527 |
| 8 | [`vim-autoformat-git`](https://aur.archlinux.org/packages/vim-autoformat-git) | [chiel92/vim-autoformat](https://github.com/chiel92/vim-autoformat) | 2112 |
| 9 | [`lmms-git`](https://aur.archlinux.org/packages/lmms-git) | [rampantpixels/rpmalloc](https://github.com/rampantpixels/rpmalloc) | 1643 |
| 10 | [`rust-gnome-git`](https://aur.archlinux.org/packages/rust-gnome-git) | [rust-gnome/gtk](https://github.com/rust-gnome/gtk) | 1273 |

The star counts show these upstream GitHub repositories are pretty popular. The packages, however, all have (near) zero popularity scores, telling us that they are not commonly used.

### What About the Official Repositories?
Up until this point, we only looked at AUR packages. Packages in the official Arch Linux repositories also use `PKGBUILD` files and GitHub repositories, making them susceptible to repo jacking attacks too.

Unfortunately, the official repositories do not publish `.SRCINFO` for its packages. This means we need to rely solely on `PKGBUILD` files, essentially Bash scripts, to parse the source URLs for each package. We did a regex search for GitHub URLs in each package's `PKGBUILD` file to get a list of GitHub repositories. Keep in mind that this process is error-prone and requires manual validation.

We performed the same analysis we did for AUR packages and found nine packages (in the `community` repository):

|                             | **Integrity verification** | **No integrity verification** |
| **Repository exists**       | 8 package (type **_11_**) | 1 packages (type **_21_**) |
| **Repository doesn't exist**| 0 packages (type **_12_**) | 0 packages (type **_22_**) |

It is expected to find no packages of type **_12_** and **_22_**, because packages in the official repositories are actively maintained.

The official repositories work differently from the AUR in that they publish pre-built binaries instead of letting users pull and build the external sources themselves. This means that packages of type **_11_** are not impacted by repo jacking, until a maintainer rebuilds the pre-built binaries and notices that the build fails because the integrity verification check fails.

The type **_21_** package is vulnerable. The vulnerability can be exploited when a maintainer rebuilds the package. An attacker could publish a copy of the legitimate GitHub repository, including malware, to the repo jacked GitHub repository. When the maintainer rebuilds and releases the new package, they would release a malicious version.

The vulnerable package in question is:

| Package            | GitHub Repository   | Type |
|--------------------|--------------------------------| |
| [`blackmagic`](https://archlinux.org/packages/community/x86_64/blackmagic) | [blacksphere/blackmagic](https://github.com/blacksphere/blackmagic) | **_21_** |

As said before, we registered the `blacksphere` GitHub account to prevent others from exploiting the vulnerability.

### Discussion
When discussing the AUR, it is important to first note the bold disclaimer on the front page:
> **DISCLAIMER: AUR packages are user produced content. Any use of the provided files is at your own risk.**

This disclaimer reminds us that the AUR is essentially unvalidated content, and one should always check what they are installing. That being said, the vulnerability we analyzed in this blog post, repo jacking, is not easy to notice if you are not explicitly looking for it. It is not easy to notice, because the fundamental vulnerability is not in the AUR or the Arch Build System, but rather in the references to GitHub.

Because GitHub helpfully redirects renamed usernames, packages will not notice or be notified when the owner of an upstream repository changes their name, leaving them vulnerable. This leaves it up to the package maintainers (and users) to regularly verify the upstream repositories. On the other hand GitHub users are often not aware of all the downstream packages and references pointing to their repositories. This inherent disconnect leaves many AUR packages vulnerable, as we saw.

The AUR disclaimer does not apply to the official Arch Linux repositories and users should be able to expect these packages to work properly. However, as we saw even a package in the community repositories is vulnerable. As these packages are actively maintained and monitored, it shows how hard it is to detect this vulnerability if you are not explicitly looking for it. We notified the [Arch Linux Security team](https://wiki.archlinux.org/title/Arch_Security_Team) (in November 2022) of the issues.

The [Arch package guidelines](https://wiki.archlinux.org/title/Arch_package_guidelines#Package_sources) provide guidance for package maintainers on how to secure their packages. It boils down to: use integrity verification whenever possible. Unfortunately, checksum verification is not possible on VCS source, because they are not static and PGP signed commits are often not available.

GitHub deployed a mitigation against repo jacking attacks: the _popular repository namespace retirement_. We did not discuss this mitigation in this blog post as it only applies to popular GitHub repositories. If you would like to learn more about repo jacking and the popular repository namespace retirement, please read our previous blog post [Hijacking GitHub Repositories by Deleting and Restoring Them]({% post_url 2022-12-04-gitub-popular-repository-namespace-retirement-bypass %}).
