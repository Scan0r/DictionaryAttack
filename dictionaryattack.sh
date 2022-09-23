#!/usr/bin/env bash
# -*- coding: utf-8 -*-

######################################################################
# dictionaryattack -- Performs a search between two file dictionaries,
# passwords and hashes, trying to find a correlation for every line
# between both
#
# Copyright (c) 2021,Scan0r
#
# This program is free software: you can redistribute it and/or modifyç
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# @Author       Scan0r
# @Date         25/10/2021
# @Version      0.1
######################################################################

######################################################################
#
# Global definitions
#
######################################################################

# Global script variables
SCRIPT_NAME="${0%.sh}"
SCRIPT_VERSION="0.1"
AUTHOR_NAME="DR"

# Exit and termination state variables
EXIT_SUCCESS=0
EXIT_FAILURE=-1

# Global options
CMD_OPT_SUPRESS_WARNINGS=1
CMD_OPT_ONE_LINE=1
CMD_OPT_VERBOSE=1

# Global variables
N_HASHES=0
M_PASSWORDS=0

# Font color variables
NC='\033[0m' # No Color
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'

######################################################################
#
# Auxiliary functions
#
######################################################################

# Prints the information of the script and its mode of use
#
# @param  None
# @return None
help() {
  cat <<EOF
$SCRIPT_NAME ($SCRIPT_VERSION) with ♥️ by $AUTHOR_NAME.
Script to bruteforce and correlate text plain passwords and their hashes.

  Usage: $SCRIPT_NAME [-h][-v][-w][-1] <hashes_file> <passwords_file>

Options:
  -h  prints this help
  -v  enables verbose mode
  -w  supress warnings
  -1  prints hash-password matches in one line format

EOF

  # Ends the program execution with an error
  exit "${1:-1}"
}

# Prints a formatted message of type notification
#
# @param  The message to print
# @return None
message() {
  echo -e "$SCRIPT_NAME: $1"
}

# Prints a formatted message of type notification
#
# @param  The message to print
# @return None
verbose() {
  if [[ "$CMD_OPT_VERBOSE" -eq 0 ]]; then
    echo -e "${GREEN}$SCRIPT_NAME: $1${NC}"
  fi
}

# Prints a formatted message of type warning
#
# @param  The message to print
# @return None
warning() {
  if [[ "$CMD_OPT_SUPRESS_WARNINGS" -ne 0 ]]; then
    echo -e "${YELLOW}$SCRIPT_NAME: warning: $1${NC}"
  fi
}

# Prints a formatted message of type error
#
# @param  The message to print
# @return None
error() {
  echo -e "${RED}$SCRIPT_NAME: error: $1${NC}"

  # Ends the program execution with an error
  if [[ -n "$2" ]]; then
    exit "$2"
  fi
}

is_option() {
  [[ -n "$1" && $(echo "$1" | grep -o -E "\-\w+") = "$1" ]]

  return "$?"
}

# Checks that a given argument is a file. It must exist and be legible and not
# empty
#
# @param  The path with the name of the file to check
# @return True | False
is_file() {
  # Checks the number and validity of the arguments
  if [[ "$#" -ne 1 ]]; then
    return "$EXIT_FAILURE"
  fi

  # Condition that verifies the validity of the file: not empty and readable file
  [[ -f "$1" && -s "$1" && -r "$1" ]]

  return "$?"
}

# Checks that a passed element as an argument is inside the list of elements of
# an array
#
# @param  Element to check inside the array
# @param  List of array elements
# @return True | false
in_array() {
  # Checks the number and validity of the arguments
  if [[ ! "$#" -ge 2 ]]; then
    return "$EXIT_FAILURE"
  fi

  local value="$1"
  shift

  # Iterates over the elements of the array looking for the element passed
  for elem in "$@"; do
    if [[ "$value" = "$elem" ]]; then
      return "$EXIT_SUCCESS"
    fi
  done

  return "$EXIT_FAILURE"
}

######################################################################
#
# Main functions
#
######################################################################

# Attempts to resolve the plaintext password of a given hash by comparing
# it to each of the possible lines of a given password dictionary
#
# @param  The hash to resolve
# @param  The line of the hash in the hashes file
# @param  The passwords file
# @return True | False
resolve_hash() {
  local target_hash="$1"
  local hash_line="$2"
  local pwds_file="$3"
  local pwd_line=0
  declare -a pwd_arr=()

  # Iterates over each of the passwords lines
  while read -r pwd; do
    pwd_line=$((pwd_line + 1))

    # Prints the progress
    verbose "Trying combination $hash_line/$N_HASHES:$pwd_line/$M_PASSWORDS"

    # Skips the empty lines of the password file
    if echo "$pwd" | grep -q -E "^$"; then
      warning "skipping empty line $pwd_line in passwords file"
      continue
    fi

    # Skips the lines of repeated passwords already processed
    if in_array "$pwd" "${pwd_arr[@]}"; then
      warning "skipping repeated password '$pwd'"
      continue
    fi

    # New password not repeated, it's added to the array of processed lines
    pwd_arr+=("$pwd")

    # Calculates the new password hash
    pwd_hsh=$(echo -n "$pwd" | sha256sum | cut -d' ' -f1)

    # Compares the hash with the computed hash of the password trying to find
    # a match
    if [[ "$pwd_hsh" = "$target_hash" ]]; then
      if [[ "$CMD_OPT_ONE_LINE" -eq 0 ]]; then
        message "Match found: Lines[$hash_line,$pwd_line]: ('$target_hash', '$pwd')"
      else
        message "Match found:\n Line $hash_line: hash='$target_hash'\n Line $pwd_line: pwd='$pwd'"
      fi

      return "$EXIT_SUCCESS"
    fi

    # The passwords file is dumped to the while structure to read it
    # line by line
  done < <(cat <"$pwds_file")

  return "$EXIT_FAILURE"
}

# Launches a dictionary attack against a set of hashes with a given
# dictionary of passwords
#
# @param  File with the hashes dictionary
# @param  File with the passwords dictionary
# @return None
dictionary_attack() {
  # Local variables
  local hashes_file=""
  local pwds_file=""

  # Checks the number of arguments required
  if [[ "$#" -ne 2 ]]; then
    error "Invalid number of file type arguments: $#" "$EXIT_FAILURE"
  else
    hashes_file="$1"
    pwds_file="$2"
  fi

  # Checks that the hashes file is valid.
  if ! is_file "$hashes_file"; then
    error "invalid, empty or unreadable file of hashes: '$hashes_file'" "$EXIT_FAILURE"
  fi

  # checks that the passwords file is valid.
  if ! is_file "$pwds_file"; then
    error "invalid, empty or unreadable file of passwords: '$pwds_file'" "$EXIT_FAILURE"
  fi

  # Compute the number of hashes, passwords and combinations to perform
  N_HASHES=$(wc -l "$hashes_file" | cut -d' ' -f1)
  M_PASSWORDS=$(wc -l "$pwds_file" | cut -d' ' -f1)

  verbose "Starting dictionary attack with $N_HASHES hashes and $M_PASSWORDS passwords"
  verbose "Possible combinations: $((N_HASHES * M_PASSWORDS))\n"
  sleep 1

  # Iterates over each of the lines of the hashes dictionary
  while read -r hsh other; do
    hsh_line=$((hsh_line + 1))

    # Checks the validity of the format of the line
    if [[ -n "$other" ]]; then
      warning "malformed line $hsh_line in hashes file"
      continue
    fi

    # Skips the lines of repeated hashes already processed
    if in_array "$hsh" "${hsh_arr[@]}"; then
      warning "skipping repeated hash '$hsh'"
      continue
    fi

    # New hash not repeated, it's added to the array of processed lines
    hsh_arr+=("$hsh")

    resolve_hash "$hsh" "$hsh_line" "$pwds_file"

    # If the hash couldnt be resolved, the user is warned
    if [[ "$?" -eq 1 ]]; then
      warning "password not found for hash256 '$hsh'"
    fi

    # The hashes file is dumped to the while structure to read it
    # line by line
  done < <(cat <"$hashes_file")
}

######################################################################
#
# Init function
#
######################################################################

# Main function of the program that inits the process logic
#
# @param  File with the password dictionary
# @param  File with the hashes dictionary
# @return None
main() {
  # Checks the number of arguments required by the program
  if [[ "$#" -lt 2 ]]; then
    error "Invalid number of arguments: $#\n"
    help "$EXIT_FAILURE"
  fi

  # List of files given by the user
  declare -a files=()

  for arg in "$@"; do
    if is_option "$arg"; then
      case "$arg" in
      "-h")
        help "$EXIT_SUCCESS"
        ;;
      "-v")
        CMD_OPT_VERBOSE=0
        ;;
      "-w")
        CMD_OPT_SUPRESS_WARNINGS=0
        ;;
      "-1")
        CMD_OPT_ONE_LINE=0
        ;;
      *)
        error "Invalid command line option '$arg'" "$EXIT_FAILURE"
        ;;
      esac
    else
      files+=("$arg")
    fi
  done

  # Launches the dictionary attack process
  # with the given files
  dictionary_attack "${files[@]}"
}

# The main function of the program is invoked with the same parameters received
# by the user
main "$@"
