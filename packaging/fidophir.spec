# Local Fedora 44 package built from source with locked Cargo dependencies.
# This is not a claim of Fedora distribution package-policy approval.
%global debug_package %{nil}
%{!?fidophir_version:%global fidophir_version 0.1.1}
Name:           fidophir
Version:        %{fidophir_version}
Release:        1%{?dist}
Summary:        Experimental minimal TPM-backed FIDO authenticator
License:        Apache-2.0 AND MIT AND BSD-2-Clause AND BSD-3-Clause AND Unicode-3.0 AND (Apache-2.0 WITH LLVM-exception)
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  cargo >= 1.92
BuildRequires:  rust >= 1.92
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  git
BuildRequires:  python3
BuildRequires:  clang-libs
BuildRequires:  clang-devel
BuildRequires:  pkgconf-pkg-config
BuildRequires:  glib2-devel >= 2.66
BuildRequires:  tpm2-tss-devel
BuildRequires:  systemd-rpm-macros
Requires:       systemd
Requires:       systemd-udev
Requires:       kmod
Requires:       polkit
Requires:       tpm2-tss
%{?systemd_requires}

%description
A per-user resident ES256 authenticator using OpenSK, TPM2-TSS and
native login1/polkit desktop approval. Experimental; physical-device and
browser acceptance checks are required before real-account use.

%prep
%autosetup

%build
%make_build build CARGO=cargo
python3 tools/licenses.py

%check
%make_build test CARGO=cargo

%install
%make_install BINARY=target/release/fidophir
install -Dm644 build/licenses/DEPENDENCIES.tsv %{buildroot}%{_docdir}/%{name}/DEPENDENCIES.tsv
mkdir -p %{buildroot}%{_licensedir}/%{name}/third-party
cp -a build/licenses/. %{buildroot}%{_licensedir}/%{name}/third-party/

%post
%systemd_post fidophir.target
# RPM presets configure enablement; first installation also activates this package.
if [ "$1" -eq 1 ] && [ -d /run/systemd/system ] && systemctl --quiet is-enabled fidophir.target; then
    systemctl start fidophir.target || :
fi
%{_libexecdir}/fidophir-package-setup systemctl

%preun
%systemd_preun fidophir.target

%postun
%systemd_postun_with_restart fidophir.target
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    udevadm control --reload-rules || :
    udevadm trigger --settle --action=change --subsystem-match=misc --sysname-match=uhid || :
    if [ "$(stat -c '%%G' /dev/uhid 2>/dev/null)" = fidophir ]; then
        chmod 0600 /dev/uhid && chgrp root /dev/uhid || :
    fi
fi

%files
%{_libexecdir}/fidophir
%{_libexecdir}/fidophir-package-setup
%{_unitdir}/fidophir@.service
%{_unitdir}/fidophir.target
%{_unitdir}/user@.service.wants/fidophir@.service
%{_presetdir}/00-fidophir.preset
%{_sysusersdir}/fidophir.conf
%{_modulesloaddir}/fidophir.conf
%{_udevrulesdir}/72-fidophir.rules
%{_datadir}/polkit-1/actions/org.local.fidophir.policy
%{_docdir}/fidophir/
%license %{_licensedir}/fidophir/

%changelog
* Wed Nov 04 2026 Fidophir contributors - 0.1.0-1
- Per-user authenticators activated with systemd user managers.
