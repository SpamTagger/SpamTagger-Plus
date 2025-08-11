# SpamTagger Plus

SpamTagger Plus is a continuation of the SpamTagger anti spam gateway.

## 🚧 Under Construction 🚧

Development of a new release of SpamTagger Plus is ongoing and this repository is no longer compatible with existing SpamTagger systems which are based on Debian Jessie.

There are currently no public downloads available for the release since build infrastructure is not complete and the development VM is in a non-working state and is changing too quickly to reasonably provide regular updates.

Please stay tuned for more information and feel free to discuss development in the relevant GitHub tabs.

## 👨‍💻 Development 👩‍💻

In the effort to get out a new release development is ongoing across a few different repositories:

- This repository contains the SpamTagger Plus application code. Work is ongoing to bring the codebase up to date to support the latest language and framework versions. Application services are also being modernized to run with more appropriate permissions, access an other considerations. See the [issues page](https://github.com/SpamTagger/SpamTagger-Plus/issues) for problems that need to be resolved.
- The [SpamTagger-Bootc](https://github.com/SpamTagger/SpamTagger-Bootc) repository is responsible for building SpamTagger Plus images in various formats. This is a significant divergence from how SpamTagger images were built as discussed [here](https://github.com/orgs/SpamTagger/discussions/3). It is capable of building container images, VM images and ISO installers, however work is ongoing to complete the configuration of SpamTagger Plus on top of these images.
- The [st-exim](https://github.com/SpamTagger/st-exim) repository builds custom versions of the [exim](https://github.com/exim/exim) MTA for SpamTagger appliances, since distribution provided versions are missing several necessary features. This currently builds Debian packages, but it will need to be modified to either build RPMs, or to be installed directly within the SpamTagger-Bootc `just build` action.
- The [python-mailcleaner-library](https://github.com/SpamTagger/python-mailcleaner-library) provides some internal API features, mostly for [Fail2Ban](https://github.com/fail2ban/fail2ban) integration. This should not require any significant modification, however it is eventually desired to remove this and replace it with a Perl based API, since this is the only Python code across all SpamTagger projects.
