---
layout: "post"
title:  "Command Injection in the Github Pages Build Pipeline"
date:   "2022-08-23"
author: "Joren Vrancken"
lang: "en"
---

<!--
- Github heeft een prettig programma
- GitHub Pro? Teams?
- Images
- Admin permissions are needed
 -->

Recently, I participated in the (public) [GitHub Bug Bounty](https://bounty.github.com/) (run through [HackerOne](https://hackerone.com/github)). This is a writeup of a command injection bug I submitted.

### GitHub Pages

[GitHub Pages](https://pages.github.com/) is a static content hosting service for your repositories. It allows users to host the contents of their repositories to `username.github.io` or a custom domain. It is a great service that allows users to fully manage their content with Git and deploy their content quickly (e.g. this blog is hosted on GitHub Pages).

To help users host nice looking content, GitHub Pages supports [Jekyll](https://jekyllrb.com/), a static content generation platform that turns Markdown files into hostable HTML files.
<!-- templates -->

### Custom Domains

When I started looking for potential bugs, I initally focussed on the custom domain feature of GitHub Pages. Users can point their own domains to the GitHub Pages servers (with a `CNAME` or `A` record) to host their content on their own domain.

However, as GitHub does not know who owns a domain, users are able to submit any domain they want. This creates a great oppurunity for domain takeovers (a serious problem, that might be a good subject for another blog post).

After I exhausted all my ideas (and got some domain takeover reports) on custom domains.

### Setting a Jekyll Theme

In the GitHub Pages settings of a repository, there is a _Theme Chooser_ section:
![GitHub Pages settings](/assets/github-pages-command-injection/settings-themes.png)

As its name suggests, this automates the process of changing the Jekyll theme.

The _Change theme_ button links to:

```HTTP
https://github.com/<owner>/<repo>/settings/pages/themes?select=<theme>&source=<branch>&source_dir=<directory>
```

`<theme>` is the current theme (if a theme is already selected). `<branch>` and `<directory>` are taken directly from the _Branch_ section in the Pages settings, and specify the source of the files that we want to host.

If we click the _Change theme_ button, we are taken to a new webpage:
![GitHub Pages Theme Selector](/assets/github-pages-command-injection/select-theme.png)

When we are done picking a theme and click the _Select theme_ button, GitHub makes a `POST` request:

```HTTP
POST /<owner>/<repo>/settings/pages/theme HTTP/2
Host: github.com
...

_method=put&authenticity_token=<token>&page[theme_slug]=<theme>&source=<branch>&source_dir=<directory>
```

Here we see the `source=<branch>&source_dir=<directory>` again. As we cannot change these values on the theme selector page, these have to be taken directly from the link that brought us to this page.

After the `POST` request, GitHub makes a new commit to change the Jekyll theme. GitHub makes these changes to the directory in the branch that is specified.

The commit in turn triggers a new build of GitHub Pages, which deploys the new theme. More on this in the next section.

In the Pages settings, we are only able to specify two directories: `/` (i.e. the root of the repository) and `/docs`. But what happens if we specify another directory in the theme chooser URL?

In other words, what happens if we go to

```HTTP
https://github.com/joren485/repo/settings/pages/themes?select=cayman&source=main&source_dir=/customdirectory
```

It turns out, that this is accepted behaviour and GitHub will use any directory name we provide as the source. For example, if we set `source_dir=/"test" test test>`, GitHub will use `/"test" test test>`.

![Arbitrary dir](/assets/github-pages-command-injection/arbitrary-dir.png)

GitHub is even nice enough to enable GitHub Pages and create the directory, if we did not do this ourselves.

We are now able to specify any arbitrary (branch and) directory to use as a GitHub Pages source.

### Deploying GitHub Pages

GitHub Pages builds are actually just [GitHub Actions](https://docs.github.com/en/actions) workflows [^0]. These workflows consit of three jobs:

1. `build`:
   1. Checks out the source of the repository ([`actions/checkout@v2`](https://github.com/actions/checkout)).
   2. Runs Jekyll to turn the source files into static files ([`actions/jekyll-build-pages@v1`](https://github.com/actions/jekyll-build-pages)).
   3. Uploads the static files ([`actions/upload-pages-artifact@v0`](https://github.com/actions/upload-pages-artifact)).
2. `report-build-status`: Sends telemetry data about the build processing ([`actions/deploy-pages@v1`](https://github.com/actions/deploy-pages)).
3. `deploy`: Deploys the static files ([`actions/deploy-pages@v1`](https://github.com/actions/deploy-pages))

In this writeup, we focus on `actions/upload-pages-artifact@v1`.

[The code of `actions/upload-pages-artifact@v1`](https://github.com/actions/upload-pages-artifact/blob/5abd6d2e035406f412d089536ee922a104d12f2b/action.yml):

```YAML
name: 'Upload Pages artifact'
description: 'A composite action that prepares your static assets to be deployed to GitHub Pages'
inputs:
  path:
    description: 'Path of the directoring containing the static assets.'
    required: true
    default: '_site/'
  retention-days:
    description: 'Duration after which artifact will expire in days.'
    required: false
    default: '1'
runs:
  using: composite
  steps:
    - name: Archive artifact
      shell: bash
      run: |
        tar \
          --dereference --hard-dereference \
          --directory ${{ inputs.path }} \
          -cvf ${{ runner.temp }}/artifact.tar \
          --exclude=.git \
          .
    - name: Upload artifact
      uses: actions/upload-artifact@main
      with:
        name: github-pages
        path: ${{ runner.temp }}/artifact.tar
        retention-days: ${{ inputs.retention-days }}
```

If we look at the Github Actions pipeline logs of a succesful run, we see how the `tar` command is used:

```
tar \
    --dereference --hard-dereference \
    --directory ./docs/_site \
    -cvf /home/runner/work/_temp/artifact.tar \
    --exclude=.git \
    .
```

In this case, we set the GitHub Pages directory to `/docs`. This tells us that `${{ inputs.path }}` is equal to `.<the direcotry we specify>/_site` and `${{ runner.temp }}` equals `/home/runner/work/_temp`.

In the previous section we saw that we have full control over the direcotry name. As [Linux allows virtually every character in directory names](https://en.wikipedia.org/wiki/Filename#Comparison_of_filename_limitations), we can set the directory to anything we want. So, what happens if we set the directory to something like `/ --asdf=`? Will this change the `tar` command to the following?

```bash
tar \
    --dereference --hard-dereference \
    --directory ./ --asdf=/_site \
    -cvf /home/runner/work/_temp/artifact.tar \
    --exclude=.git \
    .
```

Yes, it will:

![Tar asdf command](/assets/github-pages-command-injection/tar-command-asdf.png)

As we can see, `--asdf` is interpreted as a command line argument and not as the directory name. This means we have command injection.

### Arbitary Code Execution with `tar`

A feature of `tar` allows us to execute aribtrary commands. Adding `--checkpoint=1 --checkpoint-action="exec=id"` to a `tar` command will make it execute a command (e.g. `id`) for every processed file.

From the [man page](https://man7.org/linux/man-pages/man1/tar.1.html):

```text
--checkpoint[=N]
        Display progress messages every Nth record (default 10).

--checkpoint-action=ACTION
        Run ACTION on each checkpoint.
```

**Side note:** Using `--checkpoint-action` is one way to achieve code execution, but of course not the only way. As we have full control over the input, we can exit the `tar` command and execute arbitrary command. But by using `--checkpoint-action`, the `tar` command (and consequently the whole GitHub Actions workflow) will still succeed, making the attack less obivious.

### Putting It All Together

To recap:

1. We can craft URLs that will deploy GitHub Pages from arbitrary directories.
2. The `tar` command in the GitHub Pages build process is vulnerable to command injection.
3. We can use the `tar` command to execute arbitary commands by using `--checkpoint-action`.

### What Would an Attack Look Like?

And you might be thinking: "You found code execution on a GitHub Actions runner. Big Deal. So, what? Running code specified by users is exactly what CI runners are for. You just found a way to do it with extra steps."

This thought is correct, however,

### Fixing the Issue

GitHub resolved the problem by removing the Theme Chooser functionality and replaced it with a link to [their documentation](https://docs.github.com/en/pages/setting-up-a-github-pages-site-with-jekyll/adding-a-theme-to-your-github-pages-site-using-jekyll):

![GitHub Pages new settings](/assets/github-pages-command-injection/new-settings-themes.png)

---

<!-- Tijden -->
### Disclosure Timeline

* 2022-07-29: Notified GitHub (through Hackerone)
* 2022-07-29: First response from GitHub
* 2022-08-02: GitHub confirmed the bug
* 2022-08-23: Resolved and rewarded $4000 and GitHub Pro.

---
[^0]: [GitHub actually allows users to use GitHub Actions directly to build and deploy their GitHub Pages sites](https://github.blog/changelog/2021-12-16-github-pages-using-github-actions-for-builds-and-deployments-for-public-repositories/), to allow them to customize the deployment workflow.
