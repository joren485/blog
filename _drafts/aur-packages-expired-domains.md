---
layout: "post"
title:  "Hijacking AUR Packages by Searching for Expired Domains"
date:   "2022-10-23"
author: "Joren Vrancken"
lang: "en"
---

The [Arch User Repository](https://aur.archlinux.org/) (AUR) is a software repository for Arch Linux. It differs from the official Arch Linux repositories in that its packages are provided by its users and not officialy supported by the Arch Linux.

The lack of support is more a feature than a bug, because it allows the AUR to contain packages that are difficult to support (e.g. because of licensing issues) or are only used by a handful of users. However, the lack of support also means that there is less quality control and [bad actors can introduce malicious packages](https://securityaffairs.co/wordpress/74352/malware/arch-linux-aur-malware.html). To warn users of this risk, the AUR has a big disclaimer on the frontpage:
> **DISCLAIMER: AUR packages are user produced content. Any use of the provided files is at your own risk.**

There are multiple ways to introduce a malicious package (or malicious changes to a legitimate package) into the AUR. For example, by becoming the maintainer of orphaned packages (i.e. packages that are no longer supported by their previous maintainers) or typosquatting popular package names.

Another option is to find packages that use URLs with expired domains during their build process, register the domain and host malicious files. How many of packages are vulnerable to such an attack? Let's find out!

### `PKGBUILD` and `SRCINFO` files
The [Arch Build System](https://wiki.archlinux.org/title/Arch_Build_System) is the packaging system of Arch Linux. It is used in the official repositories, but also in the AUR. In the Arch Build System, packages consist of (at least) two files:

1. [`PKGBUILD`](https://wiki.archlinux.org/title/PKGBUILD): A Bash script that defines variables and functions required to build and install a package. For example, the `PKGBUILD` of the [zoom](https://aur.archlinux.org/packages/zoom) package:

    ```bash
    pkgname=zoom
    pkgver=5.12.2
    _subver=4816
    pkgrel=1
    pkgdesc="Video Conferencing and Web Conferencing Service"
    arch=('x86_64')
    license=('custom')
    url="https://zoom.us/"
    depends=('fontconfig' 'glib2' 'libpulse' 'libsm' 'ttf-font' 'libx11' 'libxtst' 'libxcb'
      'libxcomposite' 'libxfixes' 'libxi' 'libxcursor' 'libxkbcommon-x11' 'libxrandr'
      'libxrender' 'libxshmfence' 'libxslt' 'mesa' 'nss' 'xcb-util-image'
      'xcb-util-keysyms' 'dbus' 'libdrm')
    optdepends=('pulseaudio-alsa: audio via PulseAudio'
      'qt5-webengine: SSO login support'
      'ibus: remote control'
      'picom: extra compositor needed by some window managers for screen sharing'
      'xcompmgr: extra compositor needed by some window managers for screen sharing')
    options=(!strip)
    source=("${pkgname}-${pkgver}.${_subver}_orig_x86_64.pkg.tar.xz"::"https://cdn.zoom.us/prod/${pkgver}.${_subver}/zoom_x86_64.pkg.tar.xz")
    sha512sums=('1b7f28dedfa78998e7b36f12b16e21d79bd1a6ac2055abeb04c61ca22ffb688953f92bfdc5d7e9fd489b6b8baa936fa5fec1c78c53a085c5c9d668da436570c3')

    prepare() {
      sed -i 's/Zoom\.png/Zoom/g' "${srcdir}/usr/share/applications/Zoom.desktop"
      sed -i 's/StartupWMClass=Zoom/StartupWMClass=zoom/g' "${srcdir}/usr/share/applications/Zoom.desktop"
    }

    package() {
      cp -dpr --no-preserve=ownership opt usr "${pkgdir}"
    }
    ```

2. [`.SRCINFO`](https://wiki.archlinux.org/title/.SRCINFO): A static file containing the metadata of a package (generated from the `PKGBUILD` file) as key-value pairs. For example, the `.SRCINFO` of the [zoom](https://aur.archlinux.org/packages/zoom) package:

    ```
    pkgbase = zoom
      pkgdesc = Video Conferencing and Web Conferencing Service
      pkgver = 5.12.2
      pkgrel = 1
      url = https://zoom.us/
      arch = x86_64
      license = custom
      depends = fontconfig
      depends = glib2
      depends = libpulse
      depends = libsm
      depends = ttf-font
      depends = libx11
      depends = libxtst
      depends = libxcb
      depends = libxcomposite
      depends = libxfixes
      depends = libxi
      depends = libxcursor
      depends = libxkbcommon-x11
      depends = libxrandr
      depends = libxrender
      depends = libxshmfence
      depends = libxslt
      depends = mesa
      depends = nss
      depends = xcb-util-image
      depends = xcb-util-keysyms
      depends = dbus
      depends = libdrm
      optdepends = pulseaudio-alsa: audio via PulseAudio
      optdepends = qt5-webengine: SSO login support
      optdepends = ibus: remote control
      optdepends = picom: extra compositor needed by some window managers for screen sharing
      optdepends = xcompmgr: extra compositor needed by some window managers for screen sharing
      options = !strip
      source = zoom-5.12.2.4816_orig_x86_64.pkg.tar.xz::https://cdn.zoom.us/prod/5.12.2.4816/zoom_x86_64.pkg.tar.xz
      sha512sums = 1b7f28dedfa78998e7b36f12b16e21d79bd1a6ac2055abeb04c61ca22ffb688953f92bfdc5d7e9fd489b6b8baa936fa5fec1c78c53a085c5c9d668da436570c3

    pkgname = zoom
    ```

As we are interested in the URLs of the installation files of a package, we are looking for the `source` variables. The `source` variable defines the location of the installation files as an array. For example, Zoom has one source: `https://cdn.zoom.us/prod/5.12.2.4816/zoom_x86_64.pkg.tar.xz`. Archtictuere-specific sources can be defined using an archtictuere-specific array (e.g. `source_x86_64`).

### Getting all `.SRCINFO` files
At the time of writing, there are _85793_ packages in the AUR (the AUR provides a list of all packages at [https://aur.archlinux.org/packages.gz](https://aur.archlinux.org/packages.gz)). We will need to somehow get the `.SRCINFO` for each of them.

The AUR has an [API](https://wiki.archlinux.org/title/Aurweb_RPC_interface). However, the API has [a rate limit of 4000 requests per day](https://wiki.archlinux.org/title/Aurweb_RPC_interface#Limitations) (per IP address), making it unsuited for getting a full copy of the AUR.

Luckily, since july of this year, Arch Linux provides [an official mirror of the AUR](https://github.com/archlinux/aur) on GitHub. This is a huge repository (with a whopping _106670_ branches), that we can clone to get a full local copy (i.e. the `PKGBUILD` and `.SRCINFO` files) of the AUR. We can than use a library like [GitPython](https://gitpython.readthedocs.io/en/stable/index.html) to automatically traverse the Git repository and get the `.SRCINFO` file for each package:

```python
from git import Repo

repo = Repo("data/repos/aur")
refs = repo.remote().refs

for i, ref in enumerate(refs):
    package_name = ref.name.split("/")[-1]

    if package_name in ("HEAD", "master"):
        continue

    srcinfo = repo.commit(ref.commit).tree[".SRCINFO"].data_stream.read()

    # In this example, we just print the .SRCINFO data,
    # but we could save them as files or in a SQLite database for further analysis.
    print(package_name)
    print(srcinfo)
```

### Finding Expired Domains
Now we have all `.SRCINFO` files, we can easily iterate through them and get the value of each `source` variable (and each architcture-specific `source` variable).

The `source` variable does not only define the domain where a source files can be found, but also the URI schemas (e.g. https) to use. As some packages use sources with esoteric URI schemas (e.g. `gogdownloader://` in [gog-unreal-tournament-goty](https://aur.archlinux.org/packages/gog-unreal-tournament-goty)) and other packages have typos in their source schemes (e.g. `yhttps://` in [emacs-d-mode](https://aur.archlinux.org/packages/emacs-d-mode)), we only consider the following protocols:
* HTTPS (55047 sources)
* Git (2430 sources)
  * Git over HTTPS (28094 sources)
  * Git over HTTP (225 sources)
* HTTP (12706 sources)
* FTP (483 sources)
* SVN (81 sources)

These sources have 5333 unique root domains that we can check for expiration.

To find expired domains, we first filter out any domains have DNS `A` records, as they are still in use. To quickly perform many DNS requests we use [blechschmidt/massdns](https://github.com/blechschmidt/massdns). This is a great tool that allows us to resolve thousands of domains in seconds:

```bash
$ massdns \
  --output J \ # Output the data to JSON
  --ignore NOERROR \ # Do not output any results that return an A record.
  --outfile data/dns-output-root-domains.txt \
  -r data/resolvers \ # Use 1.1.1.1, 8.8.8.8 and 8.8.4.4 as DNS resolvers
  data/root-domains.txt
```

After this, we are left with only 44 (root) domains that do not have a `A` record associated with them. We can either manually check the WHOIS records for these domains or use some domain availibility API (e.g. [Domainr](https://domainr.com/)) to check if a domain has expired.

After filtering out some false positives, we are left with the 14 expired domains that are used in 20 packages:

| # | Domain | Packages |
| :---: | :---: | :---: |
| 0 | `acidhub.click` | [firefox-vacuum](https://aur.archlinux.org/packages/firefox-vacuum) [gvim-checkpath](https://aur.archlinux.org/packages/gvim-checkpath) [wine-pixi2](https://aur.archlinux.org/packages/wine-pixi2) [xcursor-theme-wii](https://aur.archlinux.org/packages/xcursor-theme-wii) |
| 1 | `alunamation.com` | [lightzone-free](https://aur.archlinux.org/packages/lightzone-free) |
| 2 | `chugunkov.website` | [scalafmt-native](https://aur.archlinux.org/packages/scalafmt-native) |
| 3 | `cqp.im` | [coolq-pro-bin](https://aur.archlinux.org/packages/coolq-pro-bin) |
| 4 | `crankysupertoon.live` | [gmedit-bin](https://aur.archlinux.org/packages/gmedit-bin) [mesen-s-bin](https://aur.archlinux.org/packages/mesen-s-bin) |
| 5 | `danym.org` | [polly-b-gone](https://aur.archlinux.org/packages/polly-b-gone) |
| 6 | `erwiz.de` | [erwiz](https://aur.archlinux.org/packages/erwiz) |
| 7 | `hostedinspace.de` | [totd](https://aur.archlinux.org/packages/totd) |
| 8 | `kygekteam.org` | [kygekteampmmp4](https://aur.archlinux.org/packages/kygekteampmmp4) |
| 9 | `relatif.moi` | [servicewall-git](https://aur.archlinux.org/packages/servicewall-git) |
| 10 | `semi.works` | [amuletml-bin](https://aur.archlinux.org/packages/amuletml-bin) |
| 11 | `syw4e.info` | [etherdump](https://aur.archlinux.org/packages/etherdump) |
| 12 | `tc.ink` | [nap-bin](https://aur.archlinux.org/packages/nap-bin) |
| 13 | `yugioh.vip` | [iscfpc](https://aur.archlinux.org/packages/iscfpc) [iscfpc-aarch64](https://aur.archlinux.org/packages/iscfpc-aarch64) [iscfpcx](https://aur.archlinux.org/packages/iscfpcx) |


### Checksums
Are all of these 20 packages hijackable by just registering the expired domains? No, because the Arch Build System has built-in checksum verification.

`PKGBUILD` files need to contain a hash (either CRC32, MD5, SHA-1, SHA-256, SHA-224, SHA-384, SHA-512 or BLAKE2) of each source that will be used to check the intigrity of the source files during installation. If a source does not match the provided hash, the installation will abort.

This means that if we hijack a package, we cannot host arbitrary files we want and expect them to be succesfully installed. They would need to match the hash value.

There are no pratical [pre-image attacks](https://en.wikipedia.org/wiki/Preimage_attack) against any of these hashes (with the notable exception of CRC32, which is not a cryptographic hash but an error correction code. However, CRC32 is only used by 16 packages), so we need to find a way to around the checksum verification altogether:

* Users can skip the checksum verification by passing the `--skipinteg` or the `--skipchecksums` option to [`makepkg`](https://man.archlinux.org/man/makepkg.8.en) (the command to install packages using `PKGBUILD` files) during the installation process.

* Package maintainers can bypass the checksum verification for a source by using `SKIP` instead of an actual hash. This tells `makepkg` to skip the integrity check for that particular source. For example, the [etherdu2048-cursesmp](https://aur.archlinux.org/packages/etherdump) package does not verify the integrity of its sources:
    ```bash
    pkgname=2048-curses
    pkgver=1.2
    pkgrel=0
    pkgdesc="Curses based popular game 2048 written in C"
    arch=('x86_64' 'aarch64' 'armv7h')
    url="https://github.com/theretikgm/2048-curses"
    license=('GPL')
    depends=('ncurses>=6.0-0' 'git')
    source=("git+https://github.com/theretikgm/2048-curses.git")
    sha256sums=('SKIP')
    build() {
      cd "${srcdir}/${pkgname}/src"
      make
    }

    package() {
      install "${srcdir}/${pkgname}/src/${pkgname}" -D "${pkgdir}/usr/bin/${pkgname}"
    }
    ```

Unfortunately, using `SKIP` instead of using actual hash values is quite common. We counted 30083 (35%) packages that use `SKIP` for at least one source. This means that there is a decent chance that one of the 20 packages we found use `SKIP`. We found four (and filed deletion requests for all of them).

Installing these packages is **dangerous**, because not only do they use sources with expired domains, but they also do not verify the integrity of any files downloaded from those domains.

As an aside, this is the number of uses of each hash type we counted (excluding `SKIP` values):

| Hash    | # of uses | % of total |
| :---:   | :---:     | :---: |
| SHA-256 | 54193     | 53.11%|
| MD5     | 25703     | 25.19%|
| SHA-512 | 13578     | 13.31%|
| SHA-1   | 4676      | 4.58% |
| BLAKE2  | 3682      | 3.61% |
| SHA-384 | 159       | 0.16% |
| SHA-224 | 31        | 0.03% |
| CRC32   | 16        | 0.02% |

### A Proof-of-Concept Package Hijack
Now that we have four vulnerable packages, we will perform a proof-of-concept attack to show how such an attack would work (and how easy it is to perform). We anonymized the package name and domain by `vulnerable-package` and `vulnerable-package.org`, respectively.

**Disclaimer:** _I understand that the applied anonymization is not strong and anyone that wants to find the vulnerable package will find it. I decided to publish this proof-of-concept attack, because: (a) it shows that this attack is possible on real-world packages, (b) package information is public and anybody that wants to find similarly vulnerable packages can do so, (c) the package is by definition broken and unused and (d) I notified the AUR by sending deletion requests._

The `PKGBUILD` of `vulnerable-package` looks like this:
```bash
pkgname=vulnerable-package
pkgver=4.0.0
pkgrel=2
pkgdesc="anonymized"
arch=(x86_64)
license=('GPL')
source=("https://jenkins.vulnerable-package.org/view/anonymized/job/anonymized-PHP-Binary/lastSuccessfulBuild/artifact/Linux/PHP_Linux-x86_64.tar.gz"
	"https://jenkins.vulnerable-package.org/view/anonymized/job/anonymized/lastSuccessfulBuild/artifact/start.sh"
)
sha256sums=('0ad82a11eb37ae6caddbf5d6a09a6d2e257cce3cbf5ff55e4a7465c5cf38e348'
            '601551a70f27acbf4214570532ede9eed011e0382a142e30b883ac7847b3cf51')

package() {
	mkdir $pkgdir/vulnerable-package
	cd $pkgdir/vulnerable-package
	rm $srcdir/PHP_Linux-x86_64.tar.gz
	cp -R $srcdir/* .
	chmod +x start.sh
}
sha256sums=('SKIP'
            'SKIP')
```

In short, this `PKGBUILD` downloads two files (`PHP_Linux-x86_64.tar.gz` and `start.sh`) from `https://jenkins.vulnerable-package.org/` and copies them to the `/vulnerable-package/` directory.

We can see that actual SHA-256 hashes are present, but they are overriden at the end with `SKIP` values.

#### Hijacking the Package

The first step in this attack is to buy and register `vulnerable-package.org`. This is easy enough and only costs about 10 bucks.

Next, we need a way to host files on our new domain. For this we can use a server we own or use a static content hosting provider like [GitHub Pages](https://pages.github.com/) or [Cloudflare Pages](https://pages.cloudflare.com/).

Finally, we need two files that match the path and filenames of the files that are downloaded during the installation:
1. `view/anonymized/job/anonymized-PHP-Binary/lastSuccessfulBuild/artifact/Linux/PHP_Linux-x86_64.tar.gz`
2. `view/anonymized/job/anonymized/lastSuccessfulBuild/artifact/start.sh`

We leave the file empty and add the following (benign) content to `start.sh`:
```Bash
#! /usr/bin/env bash
echo "[+] Code Execution"
```

#### Installing and Executing the Hijacked Package
When a victim installs the hijacked package, nothing out of the ordinary happens. Files are downloaded, checked and installed:

_Note: [yay](https://github.com/Jguer/yay) is a popular AUR helper, a program that automates installing AUR packages._

```
$ yay -Sy vulnerable-package
:: Synchronizing package databases...
 core is up to date
 extra is up to date
 community is up to date
 multilib is up to date
:: Checking for conflicts...
:: Checking for inner conflicts...
[Aur:1]  vulnerable-package-4.0.0-2

:: (1/1) Downloaded PKGBUILD: vulnerable-package
  1 vulnerable-package                        (Build Files Exist)
==> Diffs to show?
==> [N]one [A]ll [Ab]ort [I]nstalled [No]tInstalled or (1 2 3, 1-3, ^4)
==>
:: (1/1) Parsing SRCINFO: vulnerable-package

==> Making package: vulnerable-package 4.0.0-2
==> Retrieving sources...
  -> Downloading PHP_Linux-x86_64.tar.gz...
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100     1  100     1    0     0      4      0 --:--:-- --:--:-- --:--:--     4
  -> Downloading start.sh...
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    48  100    48    0     0    247      0 --:--:-- --:--:-- --:--:--   250
==> Validating source files with sha256sums...
    PHP_Linux-x86_64.tar.gz ... Skipped
    start.sh ... Skipped
==> Making package: vulnerable-package 4.0.0-2
==> Checking runtime dependencies...
==> Checking buildtime dependencies...
==> Retrieving sources...
  -> Found PHP_Linux-x86_64.tar.gz
  -> Found start.sh
==> Validating source files with sha256sums...
    PHP_Linux-x86_64.tar.gz ... Skipped
    start.sh ... Skipped
==> Removing existing $srcdir/ directory...
==> Extracting sources...
==> Sources are ready.
==> Making package: vulnerable-package 4.0.0-2
==> Checking runtime dependencies...
==> Checking buildtime dependencies...
==> WARNING: Using existing $srcdir/ tree
==> Entering fakeroot environment...
==> Starting package()...
==> Tidying install...
  -> Removing libtool files...
  -> Purging unwanted files...
  -> Removing static library files...
  -> Stripping unneeded symbols from binaries and libraries...
  -> Compressing man and info pages...
==> Checking for packaging issues...
==> Creating package "vulnerable-package"...
  -> Generating .PKGINFO file...
  -> Generating .BUILDINFO file...
  -> Generating .MTREE file...
  -> Compressing package...
==> Leaving fakeroot environment.
==> Finished making: vulnerable-package 4.0.0-2
==> Cleaning up...
loading packages...
resolving dependencies...
looking for conflicting packages...

Packages (1) vulnerable-package-4.0.0-2

:: Proceed with installation? [Y/n]
(1/1) checking keys in keyring
(1/1) checking package integrity
(1/1) loading package files
(1/1) checking for file conflicts
(1/1) checking available disk space
:: Processing package changes...
(1/1) installing vulnerable-package
```

But when they actually try to run the software they just installed, it actually runs our files:
```bash
$ /vulnerable-package/start.sh
[+] Code Execution
$ cat /vulnerable-package/start.sh
#! /usr/bin/env bash
echo "[+] Code Execution"
```

We have succesfully gained arbitrary code execution on a victim system!

### Disscussion
In this blog post we have shown a way to hijack existing AUR packages, by targeting the domains used in the installation process of those packages. Hijacking AUR packages is not a new concept. As we said in the introduction, hijacking AUR packages has always been possible (in multiple ways) and is a known risk.

Hijacking a package by registering domains is far harder to detect and other methods, because the change of domain ownership is not registerd within the AUR itself (unlike a malcious change to a `PKGDBUILD` file).

The best way to protect against this kind of attack is to enforce the integrity of source files by setting hash values. We saw that this is unfortunetly not done for a significant portion (35%) of packages.

To help make the AUR (slightly) safer, I have submitted deletion requests for all the vulnerable packages.

#### What About the Official Repositories?
The official Arch Linux repositories also use the Arch Build System and there are also GitHub mirrors available for these repositories:
* Core, Extra, and Testing: [archlinux/svntogit-packages](https://github.com/archlinux/svntogit-packages/)
* Community en Multilib: [archlinux/svntogit-community](https://github.com/archlinux/svntogit-community/)

Luckily, these have a higher level of quality control, and we did not find any expired domains in them.
