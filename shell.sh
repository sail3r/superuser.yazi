#!/bin/sh
#
# This script runs under the privilege-escalation tool (sudo/doas/run0), so it
# frequently executes AS ROOT with caller-supplied paths. Every invocation:
#   * takes each path as a SEPARATE argv element (never a pasted command
#     string), so word-splitting is the only hazard to guard against — handled
#     by quoting every expansion as "$var".
#   * passes `--` before operands so a filename beginning with '-' is never
#     read as an option.
#   * uses only POSIX utilities. The only non-POSIX extra is the optional
#     verbose flag (-v), GNU-coreutils only; the plugin omits it entirely on
#     BSD/busybox (see README).
#
# Usage:
#   shell.sh <op> [options] -- <path>...
#
# Ops:
#   cp    [--force] [-v] -- SRC...    copy each SRC into CWD (unique-named)
#   mv    [--force] [-v] -- SRC...    move each SRC into CWD (unique-named)
#   ln    [--relative]   -- SRC...    symlink each SRC into CWD
#   hardlink [-v]        -- SRC...    hard-link each SRC into CWD
#   rm    [--permanent]  -- PATH...   XDG-trash (default) or permanently remove
#   create  -- NAME...   touch NAME in CWD (refuse if it already exists)
#   mkdir   -- NAME...   mkdir -p NAME in CWD
#   touch   -- NAME...   touch NAME in CWD (update mtime if it exists)
#
# XDG trash: XDG_DATA_HOME (default ~/.local/share)/Trash/{files,info}, with
# a .trashinfo sidecar per entry per the freedesktop Trash spec.

set -u

# --- helpers ---------------------------------------------------------------

basename_of() {
    b=${1%/}
    b=${b##*/}
    printf '%s\n' "$b"
}

# legit_name NAME [DIR]: print the first NAME, NAME_1.ext, NAME_2.ext, ...
# that does not already exist inside DIR (default CWD).
legit_name() {
    name=$1
    dir=${2:-.}
    new=$name
    i=1
    while [ -e "$dir/$new" ]; do
        stem=${name%%.*}
        case $name in
            *.*) new=${stem}_$i.${name#*.} ;;
            *) new=${name}_$i ;;
        esac
        i=$((i + 1))
    done
    printf '%s\n' "$new"
}

# --- ops -------------------------------------------------------------------

die() {
    # POSIX die: die <exit-code> <message...>
    _code=$1
    shift
    printf '%s\n' "$*" >&2
    exit "$_code"
}

op_cp() {
    force=0
    verb=
    while [ $# -gt 0 ]; do
        case $1 in
            --force) force=1 ;;
            -v) verb=-v ;;
            --)
                shift
                break
                ;;
            *)
                printf 'shell.sh cp: unknown option %s\n' "$1" >&2
                return 2
                ;;
        esac
        shift
    done
    for p in "$@"; do
        if [ "$force" -eq 1 ]; then
            dest=$(basename_of "$p")
        else
            dest=$(legit_name "$(basename_of "$p")")
        fi
        cp -R $verb -- "$p" "./$dest"
    done
}

op_mv() {
    force=0
    verb=
    while [ $# -gt 0 ]; do
        case $1 in
            --force) force=1 ;;
            -v) verb=-v ;;
            --)
                shift
                break
                ;;
            *)
                printf 'shell.sh mv: unknown option %s\n' "$1" >&2
                return 2
                ;;
        esac
        shift
    done
    for p in "$@"; do
        if [ "$force" -eq 1 ]; then
            dest=$(basename_of "$p")
        else
            dest=$(legit_name "$(basename_of "$p")")
        fi
        mv $verb -- "$p" "./$dest"
    done
}

op_ln() {
    relative=0
    while [ $# -gt 0 ]; do
        case $1 in
            --relative) relative=1 ;;
            --)
                shift
                break
                ;;
            *)
                printf 'shell.sh ln: unknown option %s\n' "$1" >&2
                return 2
                ;;
        esac
        shift
    done
    for p in "$@"; do
        dest=$(legit_name "$(basename_of "$p")")
        if [ "$relative" -eq 1 ]; then
            # No POSIX `ln -r`. Build a relative symlink by hand: resolve the
            # target against CWD, then compute the path from ./$dest's dir.
            tgt_dir=$(dirname -- "$p")
            if tgt_abs=$(cd -- "$tgt_dir" 2> /dev/null && pwd -P); then
                abs=$tgt_abs/$(basename_of "$p")
            else
                die 2 "shell.sh ln: cannot cd into '$tgt_dir' to resolve relative target"
            fi
            # Strip the leading ./$dest's directory (CWD) prefix → target relative to CWD.
            cwd=$(pwd -P)
            case $abs in
                "$cwd"/*) rel=${abs#"$cwd"/} ;;
                *) rel=$abs ;; # fall back to absolute when not under CWD
            esac
            ln -s -- "$rel" "./$dest"
        else
            ln -s -- "$p" "./$dest"
        fi
    done
}

op_hardlink() {
    verb=
    while [ $# -gt 0 ]; do
        case $1 in
            -v) verb=-v ;;
            --)
                shift
                break
                ;;
            *)
                printf 'shell.sh hardlink: unknown option %s\n' "$1" >&2
                return 2
                ;;
        esac
        shift
    done
    for p in "$@"; do
        dest=$(legit_name "$(basename_of "$p")")
        ln $verb -- "$p" "./$dest"
    done
}

# Escape the 3 chars the Trash spec requires to be percent-encoded in an info
# Path line. (Full URL-encoding is unnecessary; only these break the format.)
info_escape() {
    printf '%s' "$1" | sed -e 's/%/%25/g' -e "s/'/%27/g" -e 's/\\/%5C/g'
}

iso_now() { date '+%Y-%m-%dT%H:%M:%S'; }

# trash_one PATH: move PATH into $XDG_DATA_HOME/Trash (default
# ~/.local/share/Trash), creating files/ and info/ as needed, with a
# .trashinfo sidecar recording the original absolute path. unique-name on
# collision. Returns non-zero on failure so callers can report it.
trash_one() {
    src=$1
    data_home=${XDG_DATA_HOME:-$HOME/.local/share}
    trash_dir=$data_home/Trash
    files_dir=$trash_dir/files
    info_dir=$trash_dir/info
    mkdir -p -- "$files_dir" "$info_dir" || return 1

    case $src in
        /*) orig=$src ;;
        *) orig=$PWD/$src ;;
    esac

    base=$(basename_of "$src")
    dest=$(legit_name "$base" "$files_dir")

    mv -- "$src" "$files_dir/$dest" || return 1

    esc=$(info_escape "$orig")
    printf '[Trash Info]\nPath=%s\nDeletionDate=%s\n' "$esc" "$(iso_now)" \
        > "$info_dir/$dest.trashinfo"
}

op_rm() {
    permanent=0
    while [ $# -gt 0 ]; do
        case $1 in
            --permanent) permanent=1 ;;
            --)
                shift
                break
                ;;
            *)
                printf 'shell.sh rm: unknown option %s\n' "$1" >&2
                return 2
                ;;
        esac
        shift
    done
    for p in "$@"; do
        if [ "$permanent" -eq 1 ]; then
            rm -rf -- "$p"
        else
            trash_one "$p" || die 1 "shell.sh rm: failed to trash '$p'"
        fi
    done
}

# create/touch/mkdir: the destination is resolved by the plugin (a simple
# name in the hovered directory), never by the user, so refusing an existing
# name is a one-line guard against clobbering when the directory changed
# between the yazi snapshot and execution.
op_create() {
    while [ $# -gt 0 ]; do
        case $1 in
            --)
                shift
                break
                ;;
            *)
                printf 'shell.sh create: unknown option %s\n' "$1" >&2
                return 2
                ;;
        esac
        shift
    done
    for p in "$@"; do
        if [ -e "$p" ]; then
            die 1 "shell.sh create: '$p' already exists"
        fi
        touch -- "$p"
    done
}

op_mkdir() {
    while [ $# -gt 0 ]; do
        case $1 in
            --)
                shift
                break
                ;;
            *)
                printf 'shell.sh mkdir: unknown option %s\n' "$1" >&2
                return 2
                ;;
        esac
        shift
    done
    for p in "$@"; do
        mkdir -p -- "$p"
    done
}

op_touch() {
    while [ $# -gt 0 ]; do
        case $1 in
            --)
                shift
                break
                ;;
            *)
                printf 'shell.sh touch: unknown option %s\n' "$1" >&2
                return 2
                ;;
        esac
        shift
    done
    for p in "$@"; do
        touch -- "$p"
    done
}

# --- dispatch --------------------------------------------------------------

op=${1:-}
[ $# -gt 0 ] && shift
case $op in
    cp) op_cp "$@" ;;
    mv) op_mv "$@" ;;
    ln) op_ln "$@" ;;
    hardlink) op_hardlink "$@" ;;
    rm) op_rm "$@" ;;
    create) op_create "$@" ;;
    mkdir) op_mkdir "$@" ;;
    touch) op_touch "$@" ;;
    *)
        printf 'shell.sh: unknown op %s\n' "$op" >&2
        exit 2
        ;;
esac
