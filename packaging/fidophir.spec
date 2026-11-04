# Local Fedora 44 package using the locked, vendored source bundle.
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
BuildRequires:  clang-libs
BuildRequires:  clang-devel
BuildRequires:  pkgconf-pkg-config
BuildRequires:  glib2-devel >= 2.66
BuildRequires:  tpm2-tss-devel
BuildRequires:  systemd-rpm-macros
Requires:       systemd
Requires:       systemd-udev
Requires:       polkit
Requires:       tpm2-tss
%{?systemd_requires}

%description
A single-owner resident ES256 authenticator using OpenSK, TPM2-TSS and
native login1/polkit desktop approval. Experimental; physical-device and
browser acceptance checks are required before real-account use.

%prep
%autosetup

%build
export CARGO_HOME="$PWD/.cargo-home"
%make_build build CARGO=cargo

%check
export CARGO_HOME="$PWD/.cargo-home"
%make_build test CARGO=cargo

%install
%make_install BINARY=target/release/fidophir
install -Dm644 DEPENDENCIES.tsv %{buildroot}%{_docdir}/%{name}/DEPENDENCIES.tsv
# Keep complete bundled source licenses, not just the host's license.
mkdir -p %{buildroot}%{_licensedir}/%{name}/third-party
cp -a licenses/. %{buildroot}%{_licensedir}/%{name}/third-party/

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%{_libexecdir}/fidophir
%{_unitdir}/fidophir.service
%{_sysusersdir}/fidophir.conf
%{_modulesloaddir}/fidophir.conf
%{_udevrulesdir}/72-fidophir.rules
%{_presetdir}/00-fidophir.preset
%{_datadir}/polkit-1/actions/org.local.fidophir.policy
%{_docdir}/fidophir/
%license %{_licensedir}/fidophir/

%changelog
* Wed Nov 04 2026 Fidophir contributors - 0.1.0-1
- Initial experimental implementation; no automatic activation.
