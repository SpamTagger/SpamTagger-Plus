#!/usr/bin/env bash

dnf -y install --setopt=install_weak_deps=False --allowerasing \
  perl-Perl-Critic
  
prove /usr/spamtagger/tests/
