#!/usr/bin/env bash

# (Re)enable Enterprise Linux repo which contains Perl::Critic
dnf -y install --setopt=install_weak_deps=False --allowerasing \
  epel-release

# Install Perl::Critic which provides `prove` with TAP compatible testing
dnf -y install --setopt=install_weak_deps=False --allowerasing \
  perl \
  perl-Perl-Critic \
  perl-Test2-Suite

prove /usr/spamtagger/tests/
