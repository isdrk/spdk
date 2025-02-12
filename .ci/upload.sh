#!/bin/bash -eEx
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

get_releasever() {

    # rhel RPM macro should be available in centos >= 7
    local releasever=$(rpm --eval "%{?rhel}")

    if [ -z $releasever ]; then
        # OpenEulerOS
        if [ -f /etc/os-release ]; then
            source /etc/os-release
            if [ $ID == "openEuler" ]; then
                # 20.03
                if [ $VERSION_ID == "20.03" ]; then
                    releasever="openEuler-20.03"
                fi
            fi
        fi
    fi

    echo $releasever
}

get_os_name() {
    . /etc/os-release
    echo "${ID}_${VERSION_ID}"
}

upload_deb_urm() {
    # Import gpg key
    gpg --import ${GPG_KEY_PATH}

    shopt -s nullglob

    deb_pkgs=(${name}*${VER}-${REV}_{${arch},all}*.{d,}deb)
    for deb_pkg in ${deb_pkgs[@]}; do
        test -e $deb_pkg
        echo "INFO: Signing package ${deb_pkg##*/}"
        # Debian 12 doesn't have dpkg-sig, so use debsigs
        if [[ "$(get_os_name)" == "debian_12" ]]; then
            debsigs --sign=origin -k ${gpg_key_name} ${deb_pkg}
        else
            dpkg-sig -k ${gpg_key_name} -s builder ${deb_pkg}
        fi
        MD5=$(md5sum $deb_pkg | awk '{print $1}')
        SHA1=$(shasum -a 1 $deb_pkg | awk '{ print $1 }')
        SHA256=$(shasum -a 256 $deb_pkg | awk '{ print $1 }')
        if [[ $deb_pkg =~ "_all.deb" ]]; then
            upload_url_urm="${REPO_URL}/${name}/${codename}/${STAGE}/${VER}/${deb_pkg};deb.distribution=${codename};deb.component=${repo_name};deb.architecture=all"
        else
            upload_url_urm="${REPO_URL}/${name}/${codename}/${STAGE}/${VER}/${deb_pkg};deb.distribution=${codename};deb.component=${repo_name};deb.architecture=${arch}"
        fi
        echo "INFO: Uploading package ${deb_pkg} to ${upload_url_urm}"
        curl --fail -u "${REPO_USER}:${REPO_PASS}" -X PUT \
            -H "X-Checksum-MD5:${MD5}" \
            -H "X-Checksum-Sha1:${SHA1}" \
            -H "X-Checksum-Sha256:${SHA256}" \
            -T "${deb_pkg}" "${upload_url_urm}"
    done
}

upload_rpm_urm() {

    releasever=$(get_releasever)
    if [ -z $releasever ]; then
        echo "[ERROR]: Unsupported distro. Skip uploading.."
        exit 1
    fi

    shopt -s nullglob

    rpms_location=(${HOME}/rpmbuild/RPMS/${arch}/${name}-*${VER}-${REV}*.rpm)
    for rpm_location in ${rpms_location[@]}; do
        MD5=$(md5sum $rpm_location | awk '{print $1}')
        SHA1=$(sha1sum $rpm_location | awk '{ print $1 }')
        SHA256=$(sha256sum $rpm_location | awk '{ print $1 }')
        test -f $rpm_location
        rpm_name="${rpm_location##*/}"
        upload_uri="${REPO_URL}/${repo_name}/${releasever}/${arch}/${rpm_name}"
        echo "INFO: Uploading ${rpm_name} to ${upload_uri}"
        curl --fail --user "${REPO_USER}:${REPO_PASS}" \
            -H "X-Checksum-MD5:${MD5}" \
            -H "X-Checksum-Sha1:${SHA1}" \
            -H "X-Checksum-Sha256:${SHA256}" \
            -T $rpm_location -X PUT \
            ${upload_uri}
    done

    srpms_location=(${HOME}/rpmbuild/SRPMS/${name}-*${VER}-${REV}*.src.rpm)
    for srpm_location in ${srpms_location[@]}; do
        MD5=$(md5sum $srpm_location | awk '{print $1}')
        SHA1=$(sha1sum $srpm_location | awk '{ print $1 }')
        SHA256=$(sha256sum $srpm_location | awk '{ print $1 }')
        test -f $srpm_location
        srpm_name="${srpm_location##*/}"
        upload_uri="${REPO_URL}/${repo_name}/${releasever}/SRPMS/${srpm_name}"
        echo "INFO: Uploading ${srpm_name} to ${upload_uri}"
        curl --fail --user "${REPO_USER}:${REPO_PASS}" \
            -H "X-Checksum-MD5:${MD5}" \
            -H "X-Checksum-Sha1:${SHA1}" \
            -H "X-Checksum-Sha256:${SHA256}" \
            -T ${srpm_location} -X PUT \
            ${upload_uri}
    done
}

upload_tar_urm() {
    pushd $HOME/rpmbuild/SOURCES
    tar_pkg_url="${name}-${VER}-${REV}.tar.gz"
    MD5=$(md5sum $tar_pkg_url | awk '{print $1}')
    SHA1=$(shasum -a 1 $tar_pkg_url | awk '{ print $1 }')
    SHA256=$(shasum -a 256 $tar_pkg_url | awk '{ print $1 }')
    upload_url_urm="${REPO_URL}/${repo_name}/${tar_pkg_url}"
    echo "INFO: Uploading package ${tar_pkg_url} to ${upload_url_urm}"
    curl --fail -u "${REPO_USER}:${REPO_PASS}" -X PUT \
        -H "X-Checksum-MD5:${MD5}" \
        -H "X-Checksum-Sha1:${SHA1}" \
        -H "X-Checksum-Sha256:${SHA256}" \
        -T "${tar_pkg_url}" "${upload_url_urm}"
    popd
}

bd=$(dirname $0)
user=${USER:-root}
: ${REPO_URL:?REPO_URL is not found!}
: ${REPO_USER:?REPO_USER is not found!}
: ${REPO_PASS:?REPO_PASS is not found!}

branch=$(git name-rev --name-only --refs *nvda* HEAD | awk -F/ '{print $NF}')

if [ -z "$VER" ]; then
    export VER=$(echo $branch | grep -o '[0-9]\+\(\.[0-9]\+\)*')
fi

name="spdk"
repo_name="${name}-${VER}"

if command -v ofed_info >/dev/null 2>&1; then
    # 4.6-1.0.1.2 => 4.6
    ofed_ver=$(ofed_info -n | cut -d - -f1)
    repo_name="${repo_name}-mlnx-ofed-${ofed_ver}"
fi

if test -n "$ghprbPullId"; then
    REV="pr${ghprbPullId}"
    repo_name="${repo_name}-pr"
    STAGE="pr"
else
    REV=${BUILD_NUMBER:-1}
    STAGE="release"
fi

if [[ -f /etc/debian_version ]]; then

    codename=$(lsb_release -cs)
    arch=$(dpkg --print-architecture)
    : ${GPG_KEY_PATH:? GPG_KEY_PATH is not found!}
    gpg_key_name=$(echo ${GPG_KEY_PATH##*/} | cut -d . -f 1)

    if [ $1 == "urm" ]; then
        REPO_URL="${REPO_URL}/sw-nbu-swx-ci-debian-local"
        upload_deb_urm
    else
        echo "Repo not selected"
        exit 1
    fi

elif [[ -f /etc/redhat-release || -f /etc/openEuler-release ]]; then

    arch=$(uname -m)

    if [ $1 == "urm" ]; then
        REPO_URL="${REPO_URL}/sw-nbu-swx-ci-rpm-local"
        upload_rpm_urm
    elif [ $1 == "tar" ]; then
        if [[ -f "$HOME/rpmbuild/SOURCES/${name}-$VER-$REV.tar.gz" ]]; then
            REPO_URL="${REPO_URL}/sw-nbu-swx-ci-generic-local/packages/tar"
            upload_tar_urm
        else
            echo "*.tar.gz file not found!"
            exit 1
        fi
    else
        echo "Repo not selected"
        exit 1
    fi

else

    echo "Not supported Linux version!"
    exit 1

fi
